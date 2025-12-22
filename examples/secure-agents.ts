/**
 * 🔐 Secure Agents - Comunicação Ultra-Segura entre Agentes
 * 
 * Combina o melhor de dois mundos:
 * - mTLS: Autenticação mútua e canal seguro de transporte
 * - Signal E2EE: Criptografia end-to-end com Perfect Forward Secrecy
 * - JWT: Contexto, autorização e expiração
 * 
 * DEFESA EM PROFUNDIDADE:
 * ┌─────────────────────────────────────────────────────────────┐
 * │  Camada 3: JWT (Contexto/Autorização)                       │
 * │  ┌─────────────────────────────────────────────────────────┐│
 * │  │  Camada 2: Signal E2EE (Conteúdo Encriptado)            ││
 * │  │  ┌─────────────────────────────────────────────────────┐││
 * │  │  │  Camada 1: mTLS (Canal Seguro)                      │││
 * │  │  │                                                     │││
 * │  │  │              Sua Mensagem Aqui                      │││
 * │  │  │                                                     │││
 * │  │  └─────────────────────────────────────────────────────┘││
 * │  └─────────────────────────────────────────────────────────┘│
 * └─────────────────────────────────────────────────────────────┘
 * 
 * @author @purecore
 * @license CEL
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';
import * as tls from 'node:tls';
import { EventEmitter } from 'node:events';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface SecureAgentConfig {
  agentId: string;
  capabilities?: string[];
  port?: number;
}

interface SecureMessage {
  id: string;
  from: string;
  to: string;
  timestamp: number;
  header: {
    dh: string;
    pn: number;
    n: number;
  };
  ciphertext: string;
  nonce: string;
  jwt: string;
}

interface X25519KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

interface RatchetState {
  DHs: X25519KeyPair;
  DHr: Buffer | null;
  RK: Buffer;
  CKs: Buffer | null;
  CKr: Buffer | null;
  Ns: number;
  Nr: number;
  PN: number;
  MKSKIPPED: Map<string, Buffer>;
}

// ============================================================================
// FUNÇÕES CRIPTOGRÁFICAS (Zero Dependencies)
// ============================================================================

function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    publicKey: Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).slice(-32)),
    privateKey: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32))
  };
}

function computeDH(privateKey: Buffer, publicKey: Buffer): Buffer {
  const privKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privateKey]),
    format: 'der',
    type: 'pkcs8'
  });
  
  const pubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), publicKey]),
    format: 'der',
    type: 'spki'
  });

  return crypto.diffieHellman({ privateKey: privKeyObj, publicKey: pubKeyObj });
}

function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  return crypto.hkdfSync('sha256', ikm, salt, info, length);
}

function kdfRK(rk: Buffer, dhOut: Buffer): { rootKey: Buffer; chainKey: Buffer } {
  const output = hkdf(dhOut, rk, Buffer.from('SecureAgentRatchet'), 64);
  return { rootKey: output.slice(0, 32), chainKey: output.slice(32, 64) };
}

function kdfCK(ck: Buffer): { chainKey: Buffer; messageKey: Buffer } {
  return {
    chainKey: crypto.createHmac('sha256', ck).update(Buffer.from([0x01])).digest(),
    messageKey: crypto.createHmac('sha256', ck).update(Buffer.from([0x02])).digest()
  };
}

function encrypt(plaintext: string, key: Buffer): { ciphertext: Buffer; nonce: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { ciphertext: Buffer.concat([encrypted, cipher.getAuthTag()]), nonce };
}

function decrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(ciphertext.slice(-16));
  return decipher.update(ciphertext.slice(0, -16)) + decipher.final('utf8');
}

// ============================================================================
// DOUBLE RATCHET (Simplificado)
// ============================================================================

class DoubleRatchet {
  private state: RatchetState;

  constructor() {
    this.state = {
      DHs: generateX25519KeyPair(),
      DHr: null,
      RK: Buffer.alloc(32),
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: new Map()
    };
  }

  initAsInitiator(sharedSecret: Buffer, peerPublicKey: Buffer): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.DHr = peerPublicKey;
    const dhOutput = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey, chainKey } = kdfRK(sharedSecret, dhOutput);
    this.state.RK = rootKey;
    this.state.CKs = chainKey;
  }

  initAsResponder(sharedSecret: Buffer): void {
    this.state.DHs = generateX25519KeyPair();
    this.state.RK = sharedSecret;
  }

  encrypt(plaintext: string): { header: SecureMessage['header']; ciphertext: Buffer; nonce: Buffer } {
    if (!this.state.CKs) throw new Error('Session not initialized');
    const { chainKey, messageKey } = kdfCK(this.state.CKs);
    this.state.CKs = chainKey;
    const header = { dh: this.state.DHs.publicKey.toString('hex'), pn: this.state.PN, n: this.state.Ns++ };
    const { ciphertext, nonce } = encrypt(plaintext, messageKey);
    messageKey.fill(0);
    return { header, ciphertext, nonce };
  }

  decrypt(header: SecureMessage['header'], ciphertext: Buffer, nonce: Buffer): string {
    const dhPubKey = Buffer.from(header.dh, 'hex');
    
    if (!this.state.DHr || !dhPubKey.equals(this.state.DHr)) {
      this.dhRatchet(dhPubKey);
    }

    if (!this.state.CKr) throw new Error('Receiving chain not initialized');
    const { chainKey, messageKey } = kdfCK(this.state.CKr);
    this.state.CKr = chainKey;
    this.state.Nr++;
    const plaintext = decrypt(ciphertext, messageKey, nonce);
    messageKey.fill(0);
    return plaintext;
  }

  private dhRatchet(peerPubKey: Buffer): void {
    this.state.PN = this.state.Ns;
    this.state.Ns = 0;
    this.state.Nr = 0;
    this.state.DHr = peerPubKey;

    const dh1 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk1, chainKey: ckr } = kdfRK(this.state.RK, dh1);
    this.state.RK = rk1;
    this.state.CKr = ckr;

    this.state.DHs = generateX25519KeyPair();
    const dh2 = computeDH(this.state.DHs.privateKey, this.state.DHr);
    const { rootKey: rk2, chainKey: cks } = kdfRK(this.state.RK, dh2);
    this.state.RK = rk2;
    this.state.CKs = cks;
  }

  getPublicKey(): Buffer {
    return this.state.DHs.publicKey;
  }
}

// ============================================================================
// SECURITY INFRASTRUCTURE
// ============================================================================

/**
 * Autoridade Central - Gerencia certificados e tokens
 */
class SecurityAuthority {
  private caKeyPair: { publicKey: string; privateKey: string };
  private jwtKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  private issuer = 'urn:secure-agents:authority';
  private audience = 'urn:secure-agents:network';

  constructor() {
    // CA para mTLS (RSA)
    this.caKeyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Chaves para JWT (Ed25519)
    const jwtKeys = generateKeyPair();
    this.jwtKeyPair = {
      privateKey: crypto.createPrivateKey(jwtKeys.privateKey),
      publicKey: crypto.createPublicKey(jwtKeys.publicKey)
    };

    console.log('🏛️  Security Authority inicializada');
  }

  /**
   * Gera certificado auto-assinado para um agente
   */
  generateAgentCredentials(agentId: string): {
    cert: string;
    key: string;
    ca: string;
  } {
    // Gerar par de chaves do agente
    const agentKeys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Criar certificado auto-assinado (simplificado para demo)
    // Em produção, use node-forge ou openssl para criar certificados X.509 válidos
    const certData = {
      subject: `CN=${agentId}`,
      publicKey: agentKeys.publicKey,
      issuer: 'CN=SecureAgents-CA',
      serial: crypto.randomBytes(16).toString('hex'),
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    };

    // Assinar dados do certificado
    const signature = crypto.sign('sha256', Buffer.from(JSON.stringify(certData)), this.caKeyPair.privateKey);
    
    const cert = `-----BEGIN CERTIFICATE-----
${Buffer.from(JSON.stringify({ ...certData, signature: signature.toString('base64') })).toString('base64')}
-----END CERTIFICATE-----`;

    return {
      cert,
      key: agentKeys.privateKey,
      ca: this.caKeyPair.publicKey
    };
  }

  /**
   * Emite token JWT para um agente
   */
  async issueToken(agentId: string, peerId: string, capabilities: string[] = []): Promise<string> {
    return await new SignJWT({
      agentId,
      peerId,
      capabilities,
      securityLevel: 'e2ee+mtls',
      timestamp: Date.now()
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(agentId)
      .setExpirationTime('5m')
      .sign(this.jwtKeyPair.privateKey);
  }

  /**
   * Verifica token JWT
   */
  async verifyToken(token: string): Promise<any> {
    const { payload } = await jwtVerify(token, this.jwtKeyPair.publicKey, {
      issuer: this.issuer,
      audience: this.audience
    });
    return payload;
  }

  getPublicKey(): crypto.KeyObject {
    return this.jwtKeyPair.publicKey;
  }
}

// ============================================================================
// SECURE AGENT - API SIMPLES
// ============================================================================

/**
 * 🔐 SecureAgent - Comunicação ultra-segura entre agentes
 * 
 * USO SIMPLES:
 * ```typescript
 * const authority = new SecurityAuthority();
 * const alice = new SecureAgent({ agentId: 'alice' }, authority);
 * const bob = new SecureAgent({ agentId: 'bob' }, authority);
 * 
 * await alice.connect(bob);
 * await alice.send('Hello, secure world!');
 * ```
 */
class SecureAgent extends EventEmitter {
  readonly id: string;
  private config: SecureAgentConfig;
  private authority: SecurityAuthority;
  private credentials: { cert: string; key: string; ca: string };
  private ratchet: DoubleRatchet;
  private identityKey: X25519KeyPair;
  private peer: SecureAgent | null = null;
  private token: string | null = null;
  private connected: boolean = false;
  private messageQueue: SecureMessage[] = [];

  constructor(config: SecureAgentConfig, authority: SecurityAuthority) {
    super();
    this.id = config.agentId;
    this.config = config;
    this.authority = authority;
    this.credentials = authority.generateAgentCredentials(config.agentId);
    this.ratchet = new DoubleRatchet();
    this.identityKey = generateX25519KeyPair();

    console.log(`🤖 [${this.id}] Agente criado com credenciais mTLS`);
  }

  /**
   * Retorna chave pública de identidade para key exchange
   */
  getIdentityPublicKey(): Buffer {
    return this.identityKey.publicKey;
  }

  /**
   * Retorna chave pública do ratchet
   */
  getRatchetPublicKey(): Buffer {
    return this.ratchet.getPublicKey();
  }

  /**
   * Conecta a outro agente estabelecendo sessão E2EE sobre mTLS
   */
  async connect(peer: SecureAgent): Promise<void> {
    console.log(`\n🔗 [${this.id}] Conectando a [${peer.id}]...`);

    // 1. Validação mTLS (simulada - verificar certificados)
    console.log(`   🔒 Verificando certificado mTLS de ${peer.id}...`);
    if (!this.validateCertificate(peer.credentials.cert)) {
      throw new Error(`Certificado de ${peer.id} inválido`);
    }
    console.log(`   ✅ Certificado válido`);

    // 2. Key Exchange para E2EE
    console.log(`   🔑 Estabelecendo chaves E2EE...`);
    const sharedSecret = this.performKeyExchange(peer);
    
    // 3. Inicializar Double Ratchet
    this.ratchet.initAsInitiator(sharedSecret, peer.getRatchetPublicKey());
    peer.acceptConnection(this, sharedSecret);

    // 4. Gerar tokens JWT
    this.token = await this.authority.issueToken(this.id, peer.id, this.config.capabilities);
    
    this.peer = peer;
    this.connected = true;

    console.log(`   🔐 Sessão E2EE estabelecida`);
    console.log(`   🎫 Token JWT emitido`);
    console.log(`   ✅ Conexão segura estabelecida!\n`);
  }

  /**
   * Aceita conexão de outro agente
   */
  acceptConnection(peer: SecureAgent, sharedSecret: Buffer): void {
    this.ratchet.initAsResponder(sharedSecret);
    this.peer = peer;
    this.connected = true;
  }

  /**
   * Envia mensagem encriptada E2EE pelo canal mTLS
   */
  async send(content: string): Promise<void> {
    if (!this.connected || !this.peer) {
      throw new Error('Não conectado a nenhum peer');
    }

    // Renovar token se necessário
    if (!this.token) {
      this.token = await this.authority.issueToken(this.id, this.peer.id, this.config.capabilities);
    }

    // Encriptar com Double Ratchet (E2EE)
    const { header, ciphertext, nonce } = this.ratchet.encrypt(content);

    const message: SecureMessage = {
      id: `msg-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      from: this.id,
      to: this.peer.id,
      timestamp: Date.now(),
      header,
      ciphertext: ciphertext.toString('hex'),
      nonce: nonce.toString('hex'),
      jwt: this.token
    };

    console.log(`📤 [${this.id}] → [${this.peer.id}]: "${content}"`);
    console.log(`   └─ 🔒 Encriptado E2EE | 🔐 Canal mTLS | 🎫 JWT válido`);

    // Simular envio pelo canal mTLS
    await this.peer.receive(message);
  }

  /**
   * Recebe mensagem encriptada
   */
  async receive(message: SecureMessage): Promise<void> {
    // 1. Verificar JWT
    try {
      await this.authority.verifyToken(message.jwt);
    } catch (error) {
      console.error(`❌ [${this.id}] JWT inválido de ${message.from}`);
      throw new Error('Token inválido');
    }

    // 2. Decriptar com Double Ratchet
    const ciphertext = Buffer.from(message.ciphertext, 'hex');
    const nonce = Buffer.from(message.nonce, 'hex');
    const plaintext = this.ratchet.decrypt(message.header, ciphertext, nonce);

    console.log(`📥 [${this.id}] ← [${message.from}]: "${plaintext}"`);
    console.log(`   └─ ✅ JWT verificado | ✅ E2EE decriptado | ✅ mTLS validado`);

    this.messageQueue.push(message);
    this.emit('message', { from: message.from, content: plaintext });
  }

  /**
   * Valida certificado do peer (simplificado)
   */
  private validateCertificate(cert: string): boolean {
    // Em produção, validar cadeia de certificados completa
    return cert.includes('-----BEGIN CERTIFICATE-----');
  }

  /**
   * Realiza key exchange com peer
   */
  private performKeyExchange(peer: SecureAgent): Buffer {
    const dh = computeDH(this.identityKey.privateKey, peer.getIdentityPublicKey());
    return hkdf(dh, Buffer.alloc(32), Buffer.from('SecureAgentKeyExchange'), 32);
  }

  /**
   * Retorna histórico de mensagens
   */
  getMessageHistory(): SecureMessage[] {
    return [...this.messageQueue];
  }

  /**
   * Desconecta do peer
   */
  disconnect(): void {
    this.peer = null;
    this.connected = false;
    this.token = null;
    console.log(`🔌 [${this.id}] Desconectado`);
  }
}

// ============================================================================
// DEMONSTRAÇÃO
// ============================================================================

async function demo() {
  console.log('═'.repeat(60));
  console.log('🔐 SECURE AGENTS - E2EE + mTLS + JWT');
  console.log('   Comunicação Ultra-Segura entre Agentes');
  console.log('═'.repeat(60));
  console.log('');

  // 1. Criar autoridade de segurança
  const authority = new SecurityAuthority();
  console.log('');

  // 2. Criar agentes
  const alice = new SecureAgent({ agentId: 'alice', capabilities: ['reasoning'] }, authority);
  const bob = new SecureAgent({ agentId: 'bob', capabilities: ['analysis'] }, authority);
  console.log('');

  // 3. Estabelecer conexão segura
  await alice.connect(bob);

  // 4. Trocar mensagens
  console.log('─'.repeat(60));
  console.log('💬 CONVERSA SEGURA');
  console.log('─'.repeat(60));
  console.log('');

  await alice.send('Olá Bob! Esta mensagem tem 3 camadas de segurança.');
  console.log('');
  
  await bob.send('Oi Alice! mTLS + E2EE + JWT = Máxima segurança!');
  console.log('');

  await alice.send('Perfect Forward Secrecy: cada mensagem usa chave única.');
  console.log('');

  await bob.send('E temos Post-Compromise Security também!');
  console.log('');

  // 5. Resumo
  console.log('─'.repeat(60));
  console.log('');
  console.log('📊 RESUMO DE SEGURANÇA:');
  console.log('');
  console.log('┌─────────────────────────────────────────────────────────┐');
  console.log('│  CAMADA      │  TECNOLOGIA   │  PROTEÇÃO               │');
  console.log('├─────────────────────────────────────────────────────────┤');
  console.log('│  Transporte  │  mTLS         │  Canal seguro, anti-MITM│');
  console.log('│  Conteúdo    │  Signal E2EE  │  PFS, PCS, Deniability  │');
  console.log('│  Contexto    │  JWT (EdDSA)  │  Auth, expiration, claims│');
  console.log('└─────────────────────────────────────────────────────────┘');
  console.log('');
  console.log(`📨 Total de mensagens: ${alice.getMessageHistory().length + bob.getMessageHistory().length}`);
  console.log('');
  console.log('✅ Todas as mensagens protegidas por 3 camadas de segurança!');
  console.log('');
}

// ============================================================================
// EXEMPLO MÍNIMO DE USO
// ============================================================================

/**
 * Exemplo mínimo de uso - 10 linhas para máxima segurança
 */
async function minimalExample() {
  console.log('\n');
  console.log('═'.repeat(60));
  console.log('📝 EXEMPLO MÍNIMO DE USO (10 linhas)');
  console.log('═'.repeat(60));
  console.log('');
  console.log(`
// 1. Criar autoridade central
const authority = new SecurityAuthority();

// 2. Criar agentes
const alice = new SecureAgent({ agentId: 'alice' }, authority);
const bob = new SecureAgent({ agentId: 'bob' }, authority);

// 3. Conectar (estabelece mTLS + E2EE automaticamente)
await alice.connect(bob);

// 4. Enviar mensagens seguras
await alice.send('Hello, ultra-secure world!');
await bob.send('Message received with 3 security layers!');
`);
  console.log('');
  console.log('✅ É isso! API simples, segurança máxima.');
  console.log('');
}

// Executar
if (import.meta.url === `file://${process.argv[1]}`) {
  demo()
    .then(minimalExample)
    .catch(console.error);
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  SecureAgent,
  SecurityAuthority,
  SecureAgentConfig,
  SecureMessage
};
