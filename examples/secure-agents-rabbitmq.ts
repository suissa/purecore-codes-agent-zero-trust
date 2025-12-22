/**
 * 🐰 Secure Agents + RabbitMQ
 * 
 * Comunicação distribuída ultra-segura entre agentes usando RabbitMQ como transporte.
 * 
 * ARQUITETURA:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                              RabbitMQ Broker                                │
 * │                         (com TLS para transporte)                           │
 * │  ┌─────────────────────────────────────────────────────────────────────────┐│
 * │  │                     Exchange: secure-agents                             ││
 * │  │  ┌──────────────────────┐         ┌──────────────────────┐              ││
 * │  │  │ Queue: agent-alice   │         │ Queue: agent-bob     │              ││
 * │  │  └──────────────────────┘         └──────────────────────┘              ││
 * │  └─────────────────────────────────────────────────────────────────────────┘│
 * └─────────────────────────────────────────────────────────────────────────────┘
 *                    │                               │
 *          ┌─────────▼─────────┐           ┌─────────▼─────────┐
 *          │  SecureAgent      │           │  SecureAgent      │
 *          │  (alice)          │◀─────────▶│  (bob)            │
 *          │                   │   E2EE    │                   │
 *          │  • Signal E2EE    │  payload  │  • Signal E2EE    │
 *          │  • JWT context    │           │  • JWT context    │
 *          └───────────────────┘           └───────────────────┘
 * 
 * CAMADAS DE SEGURANÇA:
 * 1. TLS do RabbitMQ (transporte broker ↔ agentes)
 * 2. Signal E2EE (conteúdo das mensagens)
 * 3. JWT (contexto, autorização, expiração)
 * 
 * @author @purecore
 * @license CEL
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface RabbitMQConfig {
  url: string;                    // amqp://user:pass@host:port ou amqps:// para TLS
  exchange?: string;              // Nome do exchange (default: 'secure-agents')
  tlsOptions?: {                  // Opções TLS para conexão segura ao broker
    ca?: Buffer;
    cert?: Buffer;
    key?: Buffer;
  };
}

interface SecureAgentRMQConfig {
  agentId: string;
  capabilities?: string[];
  rabbitmq: RabbitMQConfig;
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
  keyExchange?: {                 // Para estabelecimento de sessão
    identityKey: string;
    ratchetKey: string;
  };
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
// MOCK DO AMQPLIB (para demonstração sem dependência)
// Em produção, use: import * as amqp from 'amqplib';
// ============================================================================

interface MockChannel {
  assertExchange(name: string, type: string, options?: any): Promise<void>;
  assertQueue(name: string, options?: any): Promise<{ queue: string }>;
  bindQueue(queue: string, exchange: string, routingKey: string): Promise<void>;
  publish(exchange: string, routingKey: string, content: Buffer): boolean;
  consume(queue: string, callback: (msg: any) => void): Promise<void>;
  ack(msg: any): void;
  close(): Promise<void>;
}

interface MockConnection {
  createChannel(): Promise<MockChannel>;
  close(): Promise<void>;
}

// Simulador de RabbitMQ para demonstração
class RabbitMQSimulator {
  private static instance: RabbitMQSimulator;
  private queues: Map<string, Array<{ content: Buffer; fields: any }>> = new Map();
  private consumers: Map<string, (msg: any) => void> = new Map();
  private bindings: Map<string, string[]> = new Map(); // exchange -> routingKeys

  static getInstance(): RabbitMQSimulator {
    if (!this.instance) {
      this.instance = new RabbitMQSimulator();
    }
    return this.instance;
  }

  publish(exchange: string, routingKey: string, content: Buffer): boolean {
    const queueName = `agent-${routingKey}`;
    
    if (!this.queues.has(queueName)) {
      this.queues.set(queueName, []);
    }

    const msg = { 
      content, 
      fields: { routingKey, exchange },
      properties: {}
    };

    // Entrega direta se há consumer
    const consumer = this.consumers.get(queueName);
    if (consumer) {
      setImmediate(() => consumer(msg));
    } else {
      this.queues.get(queueName)!.push(msg);
    }

    return true;
  }

  consume(queue: string, callback: (msg: any) => void): void {
    this.consumers.set(queue, callback);
    
    // Processa mensagens pendentes
    const pending = this.queues.get(queue) || [];
    pending.forEach(msg => setImmediate(() => callback(msg)));
    this.queues.set(queue, []);
  }

  assertQueue(name: string): { queue: string } {
    if (!this.queues.has(name)) {
      this.queues.set(name, []);
    }
    return { queue: name };
  }
}

// Mock de conexão AMQP
async function connectToRabbitMQ(config: RabbitMQConfig): Promise<MockConnection> {
  console.log(`🐰 Conectando ao RabbitMQ: ${config.url}`);
  
  const simulator = RabbitMQSimulator.getInstance();
  
  return {
    createChannel: async (): Promise<MockChannel> => ({
      assertExchange: async () => {},
      assertQueue: async (name) => simulator.assertQueue(name),
      bindQueue: async () => {},
      publish: (exchange, routingKey, content) => simulator.publish(exchange, routingKey, content),
      consume: async (queue, callback) => simulator.consume(queue, callback),
      ack: () => {},
      close: async () => {}
    }),
    close: async () => {}
  };
}

// ============================================================================
// FUNÇÕES CRIPTOGRÁFICAS
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
// DOUBLE RATCHET
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
// SECURITY AUTHORITY (Compartilhada entre agentes)
// ============================================================================

class SecurityAuthority {
  private jwtKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  private issuer = 'urn:secure-agents:authority';
  private audience = 'urn:secure-agents:network';

  constructor() {
    const jwtKeys = generateKeyPair();
    this.jwtKeyPair = {
      privateKey: crypto.createPrivateKey(jwtKeys.privateKey),
      publicKey: crypto.createPublicKey(jwtKeys.publicKey)
    };
    console.log('🏛️  Security Authority inicializada');
  }

  async issueToken(agentId: string, peerId: string, capabilities: string[] = []): Promise<string> {
    return await new SignJWT({
      agentId,
      peerId,
      capabilities,
      securityLevel: 'e2ee+rabbitmq-tls',
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

  // Serializa chave pública para compartilhar entre processos
  exportPublicKey(): string {
    return this.jwtKeyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }
}

// ============================================================================
// SECURE AGENT COM RABBITMQ
// ============================================================================

/**
 * 🐰 SecureAgentRMQ - Agente distribuído com comunicação ultra-segura via RabbitMQ
 * 
 * USO SIMPLES:
 * ```typescript
 * const authority = new SecurityAuthority();
 * 
 * const alice = new SecureAgentRMQ({
 *   agentId: 'alice',
 *   rabbitmq: { url: 'amqps://localhost:5671' }
 * }, authority);
 * 
 * await alice.connect();
 * await alice.send('bob', 'Hello via RabbitMQ!');
 * ```
 */
class SecureAgentRMQ extends EventEmitter {
  readonly id: string;
  private config: SecureAgentRMQConfig;
  private authority: SecurityAuthority;
  private connection: MockConnection | null = null;
  private channel: MockChannel | null = null;
  private exchange: string;
  private queueName: string;
  
  // E2EE
  private identityKey: X25519KeyPair;
  private sessions: Map<string, DoubleRatchet> = new Map();
  private peerKeys: Map<string, { identityKey: Buffer; ratchetKey: Buffer }> = new Map();
  private pendingKeyExchanges: Map<string, (keys: { identityKey: Buffer; ratchetKey: Buffer }) => void> = new Map();
  
  private connected: boolean = false;
  private messageHistory: SecureMessage[] = [];

  constructor(config: SecureAgentRMQConfig, authority: SecurityAuthority) {
    super();
    this.id = config.agentId;
    this.config = config;
    this.authority = authority;
    this.exchange = config.rabbitmq.exchange || 'secure-agents';
    this.queueName = `agent-${config.agentId}`;
    this.identityKey = generateX25519KeyPair();

    console.log(`🤖 [${this.id}] Agente RabbitMQ criado`);
  }

  /**
   * Conecta ao RabbitMQ e configura filas
   */
  async connect(): Promise<void> {
    console.log(`\n🔗 [${this.id}] Conectando ao RabbitMQ...`);

    // Conectar ao broker
    this.connection = await connectToRabbitMQ(this.config.rabbitmq);
    this.channel = await this.connection.createChannel();

    // Configurar exchange e fila
    await this.channel.assertExchange(this.exchange, 'direct', { durable: true });
    await this.channel.assertQueue(this.queueName, { durable: true });
    await this.channel.bindQueue(this.queueName, this.exchange, this.id);

    // Iniciar consumidor
    await this.channel.consume(this.queueName, async (msg) => {
      if (msg) {
        await this.handleMessage(msg);
        this.channel?.ack(msg);
      }
    });

    this.connected = true;
    console.log(`   ✅ Conectado! Fila: ${this.queueName}`);
  }

  /**
   * Retorna chaves públicas para key exchange
   */
  getPublicKeys(): { identityKey: string; ratchetKey: string } {
    const ratchet = new DoubleRatchet();
    return {
      identityKey: this.identityKey.publicKey.toString('hex'),
      ratchetKey: ratchet.getPublicKey().toString('hex')
    };
  }

  /**
   * Inicia sessão E2EE com outro agente via RabbitMQ
   */
  async establishSession(peerId: string): Promise<void> {
    console.log(`\n🔐 [${this.id}] Estabelecendo sessão E2EE com ${peerId}...`);

    // Enviar request de key exchange
    const keyExchangeMsg: SecureMessage = {
      id: `kex-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      from: this.id,
      to: peerId,
      timestamp: Date.now(),
      header: { dh: '', pn: 0, n: 0 },
      ciphertext: '',
      nonce: '',
      jwt: await this.authority.issueToken(this.id, peerId, this.config.capabilities),
      keyExchange: {
        identityKey: this.identityKey.publicKey.toString('hex'),
        ratchetKey: this.getPublicKeys().ratchetKey
      }
    };

    // Aguardar resposta do peer
    const peerKeysPromise = new Promise<{ identityKey: Buffer; ratchetKey: Buffer }>((resolve) => {
      this.pendingKeyExchanges.set(peerId, resolve);
      
      // Timeout de 30s
      setTimeout(() => {
        if (this.pendingKeyExchanges.has(peerId)) {
          this.pendingKeyExchanges.delete(peerId);
          console.log(`   ⚠️ Timeout aguardando ${peerId}`);
        }
      }, 30000);
    });

    // Publicar no RabbitMQ
    this.publishToRabbitMQ(peerId, keyExchangeMsg);
    console.log(`   📤 Key exchange enviado para ${peerId}`);

    // Aguardar chaves do peer (ou usar existentes se já temos)
    let peerKeys = this.peerKeys.get(peerId);
    if (!peerKeys) {
      peerKeys = await peerKeysPromise;
    }

    // Criar sessão Double Ratchet
    const sharedSecret = this.performKeyExchange(peerKeys.identityKey);
    const ratchet = new DoubleRatchet();
    ratchet.initAsInitiator(sharedSecret, peerKeys.ratchetKey);
    this.sessions.set(peerId, ratchet);

    console.log(`   ✅ Sessão E2EE estabelecida com ${peerId}`);
  }

  /**
   * Envia mensagem encriptada E2EE via RabbitMQ
   */
  async send(peerId: string, content: string): Promise<void> {
    if (!this.connected) {
      throw new Error('Não conectado ao RabbitMQ');
    }

    // Estabelecer sessão se não existe
    let session = this.sessions.get(peerId);
    if (!session) {
      await this.establishSession(peerId);
      session = this.sessions.get(peerId);
      if (!session) {
        throw new Error(`Falha ao estabelecer sessão com ${peerId}`);
      }
    }

    // Encriptar com Double Ratchet
    const { header, ciphertext, nonce } = session.encrypt(content);

    const message: SecureMessage = {
      id: `msg-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      from: this.id,
      to: peerId,
      timestamp: Date.now(),
      header,
      ciphertext: ciphertext.toString('hex'),
      nonce: nonce.toString('hex'),
      jwt: await this.authority.issueToken(this.id, peerId, this.config.capabilities)
    };

    // Publicar no RabbitMQ
    this.publishToRabbitMQ(peerId, message);

    this.messageHistory.push(message);
    console.log(`📤 [${this.id}] → [${peerId}] via RabbitMQ: "${content}"`);
    console.log(`   └─ 🔒 E2EE | 🐰 RabbitMQ TLS | 🎫 JWT`);
  }

  /**
   * Publica mensagem no RabbitMQ
   */
  private publishToRabbitMQ(routingKey: string, message: SecureMessage): void {
    if (!this.channel) {
      throw new Error('Canal não disponível');
    }

    const content = Buffer.from(JSON.stringify(message));
    this.channel.publish(this.exchange, routingKey, content);
  }

  /**
   * Processa mensagem recebida do RabbitMQ
   */
  private async handleMessage(msg: any): Promise<void> {
    const message: SecureMessage = JSON.parse(msg.content.toString());

    // Verificar JWT
    try {
      await this.authority.verifyToken(message.jwt);
    } catch (error) {
      console.error(`❌ [${this.id}] JWT inválido de ${message.from}`);
      return;
    }

    // É um key exchange?
    if (message.keyExchange) {
      await this.handleKeyExchange(message);
      return;
    }

    // Decriptar mensagem normal
    let session = this.sessions.get(message.from);
    if (!session) {
      // Aguardar sessão ser estabelecida
      const peerKeys = this.peerKeys.get(message.from);
      if (peerKeys) {
        const sharedSecret = this.performKeyExchange(peerKeys.identityKey);
        session = new DoubleRatchet();
        session.initAsResponder(sharedSecret);
        this.sessions.set(message.from, session);
      } else {
        console.error(`❌ [${this.id}] Sessão não encontrada com ${message.from}`);
        return;
      }
    }

    const ciphertext = Buffer.from(message.ciphertext, 'hex');
    const nonce = Buffer.from(message.nonce, 'hex');
    const plaintext = session.decrypt(message.header, ciphertext, nonce);

    this.messageHistory.push(message);
    console.log(`📥 [${this.id}] ← [${message.from}] via RabbitMQ: "${plaintext}"`);
    console.log(`   └─ ✅ JWT | ✅ E2EE | ✅ RabbitMQ`);

    this.emit('message', { from: message.from, content: plaintext, message });
  }

  /**
   * Processa key exchange
   */
  private async handleKeyExchange(message: SecureMessage): Promise<void> {
    if (!message.keyExchange) return;

    const peerKeys = {
      identityKey: Buffer.from(message.keyExchange.identityKey, 'hex'),
      ratchetKey: Buffer.from(message.keyExchange.ratchetKey, 'hex')
    };

    // Armazenar chaves do peer
    this.peerKeys.set(message.from, peerKeys);

    // Resolver promessa pendente se houver
    const pendingResolve = this.pendingKeyExchanges.get(message.from);
    if (pendingResolve) {
      pendingResolve(peerKeys);
      this.pendingKeyExchanges.delete(message.from);
    }

    // Responder com nossas chaves
    const responseMsg: SecureMessage = {
      id: `kex-resp-${Date.now()}`,
      from: this.id,
      to: message.from,
      timestamp: Date.now(),
      header: { dh: '', pn: 0, n: 0 },
      ciphertext: '',
      nonce: '',
      jwt: await this.authority.issueToken(this.id, message.from, this.config.capabilities),
      keyExchange: {
        identityKey: this.identityKey.publicKey.toString('hex'),
        ratchetKey: this.getPublicKeys().ratchetKey
      }
    };

    this.publishToRabbitMQ(message.from, responseMsg);

    // Inicializar sessão como responder
    const sharedSecret = this.performKeyExchange(peerKeys.identityKey);
    const ratchet = new DoubleRatchet();
    ratchet.initAsResponder(sharedSecret);
    this.sessions.set(message.from, ratchet);

    console.log(`🔑 [${this.id}] Key exchange com ${message.from} concluído`);
  }

  /**
   * Realiza key exchange com peer
   */
  private performKeyExchange(peerIdentityKey: Buffer): Buffer {
    const dh = computeDH(this.identityKey.privateKey, peerIdentityKey);
    return hkdf(dh, Buffer.alloc(32), Buffer.from('SecureAgentKeyExchange'), 32);
  }

  /**
   * Retorna histórico de mensagens
   */
  getMessageHistory(): SecureMessage[] {
    return [...this.messageHistory];
  }

  /**
   * Desconecta do RabbitMQ
   */
  async disconnect(): Promise<void> {
    if (this.channel) {
      await this.channel.close();
    }
    if (this.connection) {
      await this.connection.close();
    }
    this.connected = false;
    console.log(`🔌 [${this.id}] Desconectado do RabbitMQ`);
  }
}

// ============================================================================
// DEMONSTRAÇÃO
// ============================================================================

async function demo() {
  console.log('═'.repeat(65));
  console.log('🐰 SECURE AGENTS + RABBITMQ');
  console.log('   Comunicação Distribuída Ultra-Segura');
  console.log('═'.repeat(65));
  console.log('');

  // 1. Criar autoridade de segurança (compartilhada)
  const authority = new SecurityAuthority();
  console.log('');

  // 2. Criar agentes (poderiam estar em processos/máquinas diferentes)
  const alice = new SecureAgentRMQ({
    agentId: 'alice',
    capabilities: ['reasoning'],
    rabbitmq: { url: 'amqps://localhost:5671' }  // TLS
  }, authority);

  const bob = new SecureAgentRMQ({
    agentId: 'bob',
    capabilities: ['analysis'],
    rabbitmq: { url: 'amqps://localhost:5671' }
  }, authority);

  console.log('');

  // 3. Conectar ao RabbitMQ
  await alice.connect();
  await bob.connect();
  console.log('');

  // 4. Estabelecer sessão E2EE (troca de chaves via RabbitMQ)
  // Alice inicia a sessão
  await alice.establishSession('bob');
  
  // Pequeno delay para garantir que bob recebeu o key exchange
  await new Promise(resolve => setTimeout(resolve, 100));

  // 5. Trocar mensagens
  console.log('');
  console.log('─'.repeat(65));
  console.log('💬 CONVERSA VIA RABBITMQ (E2EE)');
  console.log('─'.repeat(65));
  console.log('');

  await alice.send('bob', 'Olá Bob! Mensagem via RabbitMQ com E2EE!');
  await new Promise(resolve => setTimeout(resolve, 100));

  await bob.send('alice', 'Oi Alice! Recebido com segurança total!');
  await new Promise(resolve => setTimeout(resolve, 100));

  await alice.send('bob', 'Cada mensagem usa uma chave diferente (PFS).');
  await new Promise(resolve => setTimeout(resolve, 100));

  await bob.send('alice', 'E o RabbitMQ usa TLS para o transporte!');
  await new Promise(resolve => setTimeout(resolve, 100));

  // 6. Resumo
  console.log('');
  console.log('─'.repeat(65));
  console.log('');
  console.log('📊 ARQUITETURA DE SEGURANÇA:');
  console.log('');
  console.log('┌─────────────────────────────────────────────────────────────────┐');
  console.log('│  CAMADA           │  TECNOLOGIA      │  PROTEÇÃO                │');
  console.log('├─────────────────────────────────────────────────────────────────┤');
  console.log('│  Broker           │  RabbitMQ + TLS  │  Transporte seguro       │');
  console.log('│  Mensagem         │  Signal E2EE     │  Conteúdo encriptado     │');
  console.log('│  Contexto         │  JWT (EdDSA)     │  Auth, expiration        │');
  console.log('└─────────────────────────────────────────────────────────────────┘');
  console.log('');
  console.log('🔒 Mesmo que o RabbitMQ seja comprometido, as mensagens');
  console.log('   permanecem seguras devido à encriptação E2EE!');
  console.log('');
  console.log(`📨 Total de mensagens: ${alice.getMessageHistory().length + bob.getMessageHistory().length}`);
  console.log('');

  // Cleanup
  await alice.disconnect();
  await bob.disconnect();

  console.log('✅ Demonstração concluída!');
}

// ============================================================================
// EXEMPLO DE USO COM RABBITMQ REAL
// ============================================================================

async function realWorldExample() {
  console.log('\n');
  console.log('═'.repeat(65));
  console.log('📝 EXEMPLO COM RABBITMQ REAL');
  console.log('═'.repeat(65));
  console.log('');
  console.log(`
// 1. Instalar amqplib
// bun add amqplib @types/amqplib

// 2. Substituir o mock por import real:
// import * as amqp from 'amqplib';

// 3. Configurar conexão com TLS:
const alice = new SecureAgentRMQ({
  agentId: 'alice',
  rabbitmq: {
    url: 'amqps://user:pass@rabbitmq.example.com:5671',
    exchange: 'secure-agents',
    tlsOptions: {
      ca: fs.readFileSync('/path/to/ca.pem'),
      cert: fs.readFileSync('/path/to/client.pem'),
      key: fs.readFileSync('/path/to/client-key.pem')
    }
  }
}, authority);

// 4. Usar normalmente:
await alice.connect();
await alice.send('bob', 'Hello via real RabbitMQ!');

// 5. Escutar mensagens:
alice.on('message', ({ from, content }) => {
  console.log(\`Mensagem de \${from}: \${content}\`);
});
`);
  console.log('');
}

// Executar
if (import.meta.url === `file://${process.argv[1]}`) {
  demo()
    .then(realWorldExample)
    .catch(console.error);
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  SecureAgentRMQ,
  SecurityAuthority,
  SecureAgentRMQConfig,
  RabbitMQConfig,
  SecureMessage
};
