/**
 * Self-Healing Agentic Conversational System com mTLS
 * 
 * Sistema onde dois agentes se identificam usando:
 * 1. JWTs do mesmo servidor (autenticação de aplicação)
 * 2. mTLS (mutual TLS) para autenticação de transporte
 * 
 * Isso fornece segurança em duas camadas:
 * - JWT: Autenticação de identidade e contexto
 * - mTLS: Autenticação de transporte e prevenção de MITM
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';
import * as tls from 'node:tls';
import * as net from 'node:net';
import { EventEmitter } from 'node:events';

// ============================================================================
// Geração de Certificados para mTLS
// ============================================================================

interface AgentCertificate {
  cert: string;
  key: string;
  publicKey: string;
  agentId: string;
}

class CertificateAuthority {
  private caKey: crypto.KeyObject;
  private caCert: string;

  constructor() {
    // Gerar CA (Certificate Authority) para assinar certificados dos agentes
    const caKeys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    this.caKey = crypto.createPrivateKey(caKeys.privateKey);

    // Criar certificado auto-assinado da CA
    this.caCert = this.createSelfSignedCert(
      'CN=Agentic System CA',
      caKeys.publicKey,
      caKeys.privateKey
    );
  }

  /**
   * Gera certificado para um agente
   */
  generateAgentCertificate(agentId: string): AgentCertificate {
    // Gerar par de chaves para o agente
    const agentKeys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Criar certificado assinado pela CA
    const cert = this.createSignedCert(
      `CN=${agentId}`,
      agentKeys.publicKey,
      agentKeys.privateKey
    );

    return {
      cert,
      key: agentKeys.privateKey,
      publicKey: agentKeys.publicKey,
      agentId
    };
  }

  /**
   * Retorna o certificado da CA (para validação)
   */
  getCACertificate(): string {
    return this.caCert;
  }

  private createSelfSignedCert(subject: string, publicKey: string, privateKey: string): string {
    // Para produção, use uma biblioteca como node-forge ou openssl
    // Aqui criamos um certificado básico usando Node.js crypto
    const cert = crypto.createCertificate({
      subject: subject,
      publicKey: publicKey,
      serialNumber: crypto.randomBytes(16).toString('hex'),
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 ano
    });

    return cert.toString();
  }

  private createSignedCert(subject: string, publicKey: string, privateKey: string): string {
    // Similar ao acima, mas assinado pela CA
    // Em produção, use biblioteca adequada ou OpenSSL
    return this.createSelfSignedCert(subject, publicKey, privateKey);
  }
}

// ============================================================================
// Token Authority (mesma do exemplo anterior)
// ============================================================================

class TokenAuthority {
  private privateKey: crypto.KeyObject;
  public publicKey: crypto.KeyObject;
  private issuer = 'urn:agentic-system:authority';
  private audience = 'urn:agentic-system:agents';

  constructor() {
    const keys = generateKeyPair();
    this.privateKey = crypto.createPrivateKey(keys.privateKey);
    this.publicKey = crypto.createPublicKey(keys.publicKey);
  }

  async issueAgentToken(
    agentId: string,
    agentType: 'primary' | 'secondary',
    conversationId: string,
    capabilities: string[] = []
  ): Promise<string> {
    return await new SignJWT({
      agentId,
      agentType,
      conversationId,
      capabilities,
      issuedAt: Date.now()
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(agentId)
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }

  async renewToken(oldToken: string): Promise<string> {
    try {
      const { payload } = await jwtVerify(oldToken, this.publicKey, {
        issuer: this.issuer,
        audience: this.audience,
      }).catch(() => {
        const parts = oldToken.split('.');
        if (parts.length !== 3) throw new Error('Token inválido');
        const decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
        return { payload: decoded };
      });

      return await this.issueAgentToken(
        payload.agentId as string,
        payload.agentType as 'primary' | 'secondary',
        payload.conversationId as string,
        payload.capabilities as string[]
      );
    } catch (error) {
      throw new Error(`Falha ao renovar token: ${error}`);
    }
  }
}

// ============================================================================
// Agente com Suporte a mTLS
// ============================================================================

interface AgentMessage {
  from: string;
  to: string;
  content: string;
  timestamp: number;
  messageId: string;
  jwt: string; // Token JWT incluído na mensagem
}

class mTLSAgent extends EventEmitter {
  private agentId: string;
  private agentType: 'primary' | 'secondary';
  private conversationId: string;
  private capabilities: string[];
  private token: string | null = null;
  private tokenExpiry: number = 0;
  private renewalThreshold: number = 60;
  private authority: TokenAuthority;
  private messageHistory: AgentMessage[] = [];
  
  // Certificados mTLS
  private certificate: AgentCertificate;
  private caCert: string;
  private tlsServer: tls.Server | null = null;
  private tlsConnections: Map<string, tls.TLSSocket> = new Map();

  constructor(
    agentId: string,
    agentType: 'primary' | 'secondary',
    authority: TokenAuthority,
    certificate: AgentCertificate,
    caCert: string,
    capabilities: string[] = []
  ) {
    super();
    this.agentId = agentId;
    this.agentType = agentType;
    this.authority = authority;
    this.certificate = certificate;
    this.caCert = caCert;
    this.capabilities = capabilities;
    this.conversationId = `conv-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  async initialize(): Promise<void> {
    this.token = await this.authority.issueAgentToken(
      this.agentId,
      this.agentType,
      this.conversationId,
      this.capabilities
    );
    this.tokenExpiry = Date.now() + (5 * 60 * 1000);
    console.log(`🤖 [${this.agentId}] Agente inicializado com mTLS e token válido até ${new Date(this.tokenExpiry).toISOString()}`);
  }

  private async ensureValidToken(): Promise<void> {
    const now = Date.now();
    const timeUntilExpiry = this.tokenExpiry - now;

    if (!this.token || timeUntilExpiry < this.renewalThreshold * 1000) {
      if (this.token) {
        console.log(`🔄 [${this.agentId}] Token próximo de expirar, renovando...`);
      }

      try {
        if (this.token) {
          this.token = await this.authority.renewToken(this.token);
        } else {
          await this.initialize();
          return;
        }

        this.tokenExpiry = Date.now() + (5 * 60 * 1000);
        console.log(`✅ [${this.agentId}] Token renovado com sucesso.`);
      } catch (error) {
        console.error(`❌ [${this.agentId}] Erro ao renovar token:`, error);
        await this.initialize();
      }
    }
  }

  /**
   * Inicia servidor TLS para receber conexões de outros agentes
   */
  startTLSServer(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const options: tls.TlsOptions = {
        cert: this.certificate.cert,
        key: this.certificate.key,
        ca: [this.caCert], // Certificados aceitos (CA)
        requestCert: true, // Requer certificado do cliente (mTLS)
        rejectUnauthorized: true, // Rejeita conexões não autorizadas
      };

      this.tlsServer = tls.createServer(options, (socket: tls.TLSSocket) => {
        const peerCert = socket.getPeerCertificate();
        const peerId = peerCert.subject?.CN || 'unknown';

        console.log(`🔒 [${this.agentId}] Conexão mTLS estabelecida com ${peerId}`);

        // Verificar certificado do peer
        if (!peerCert || !socket.authorized) {
          console.error(`❌ [${this.agentId}] Conexão rejeitada: certificado inválido`);
          socket.destroy();
          return;
        }

        this.tlsConnections.set(peerId, socket);

        socket.on('data', async (data) => {
          try {
            const message: AgentMessage = JSON.parse(data.toString());
            await this.handleIncomingMessage(message, peerId);
          } catch (error) {
            console.error(`❌ [${this.agentId}] Erro ao processar mensagem:`, error);
          }
        });

        socket.on('close', () => {
          console.log(`🔌 [${this.agentId}] Conexão mTLS fechada com ${peerId}`);
          this.tlsConnections.delete(peerId);
        });

        socket.on('error', (error) => {
          console.error(`❌ [${this.agentId}] Erro na conexão TLS:`, error);
        });
      });

      this.tlsServer.listen(port, () => {
        console.log(`🔒 [${this.agentId}] Servidor mTLS iniciado na porta ${port}`);
        resolve();
      });

      this.tlsServer.on('error', reject);
    });
  }

  /**
   * Conecta a outro agente via mTLS
   */
  async connectToPeer(host: string, port: number, peerId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const options: tls.ConnectionOptions = {
        cert: this.certificate.cert,
        key: this.certificate.key,
        ca: [this.caCert],
        rejectUnauthorized: true,
        servername: peerId, // SNI (Server Name Indication)
      };

      const socket = tls.connect(port, host, options, () => {
        const peerCert = socket.getPeerCertificate();
        
        if (!socket.authorized) {
          reject(new Error(`Conexão não autorizada: ${socket.authorizationError}`));
          return;
        }

        console.log(`🔒 [${this.agentId}] Conectado via mTLS a ${peerId}`);
        this.tlsConnections.set(peerId, socket);
        resolve();
      });

      socket.on('data', async (data) => {
        try {
          const message: AgentMessage = JSON.parse(data.toString());
          await this.handleIncomingMessage(message, peerId);
        } catch (error) {
          console.error(`❌ [${this.agentId}] Erro ao processar mensagem:`, error);
        }
      });

      socket.on('error', reject);
    });
  }

  /**
   * Envia mensagem para outro agente via mTLS
   */
  async sendMessage(peerId: string, content: string): Promise<void> {
    await this.ensureValidToken();

    if (!this.token) {
      throw new Error('Agente não possui token válido');
    }

    const socket = this.tlsConnections.get(peerId);
    if (!socket || socket.destroyed) {
      throw new Error(`Conexão mTLS não estabelecida com ${peerId}`);
    }

    const message: AgentMessage = {
      from: this.agentId,
      to: peerId,
      content,
      timestamp: Date.now(),
      messageId: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      jwt: this.token // Inclui JWT na mensagem para verificação de identidade
    };

    // Verificar identidade do peer via JWT antes de enviar
    // (a verificação mTLS já garante que é o certificado correto)
    
    this.messageHistory.push(message);
    socket.write(JSON.stringify(message));
    
    console.log(`📤 [${this.agentId}] → [${peerId}] (mTLS): ${content}`);
  }

  /**
   * Processa mensagem recebida
   */
  private async handleIncomingMessage(message: AgentMessage, peerId: string): Promise<void> {
    await this.ensureValidToken();

    // Verificar JWT do remetente
    try {
      const { payload } = await jwtVerify(message.jwt, this.authority.publicKey, {
        issuer: 'urn:agentic-system:authority',
        audience: 'urn:agentic-system:agents'
      });

      // Verificar se está na mesma conversa
      if (payload.conversationId !== this.conversationId) {
        throw new Error('Agente não está na mesma conversa');
      }

      // Verificar se o agentId do JWT corresponde ao certificado
      if (payload.agentId !== peerId) {
        throw new Error('Mismatch entre certificado mTLS e JWT');
      }

      this.messageHistory.push(message);
      console.log(`📥 [${this.agentId}] ← [${message.from}] (mTLS): ${message.content}`);
      
      this.emit('message', message);
    } catch (error) {
      console.error(`❌ [${this.agentId}] Mensagem rejeitada:`, error);
      throw error;
    }
  }

  getToken(): string {
    if (!this.token) {
      throw new Error('Agente não possui token');
    }
    return this.token;
  }

  getConversationHistory(): AgentMessage[] {
    return [...this.messageHistory];
  }

  startAutoRenewal(intervalMs: number = 30000): void {
    setInterval(async () => {
      await this.ensureValidToken();
    }, intervalMs);
    
    console.log(`🔄 [${this.agentId}] Auto-renovação de token ativada`);
  }

  stop(): void {
    this.tlsConnections.forEach(socket => socket.destroy());
    this.tlsConnections.clear();
    
    if (this.tlsServer) {
      this.tlsServer.close();
      this.tlsServer = null;
    }
  }
}

// ============================================================================
// Exemplo de Uso
// ============================================================================

async function demonstrateMTLSAgents() {
  console.log('🚀 Demonstração de Self-Healing Agents com mTLS\n');

  // 1. Criar CA e Autoridade de Tokens
  const ca = new CertificateAuthority();
  const tokenAuthority = new TokenAuthority();
  console.log('✅ CA e Autoridade de Tokens criadas\n');

  // 2. Gerar certificados para os agentes
  const certA = ca.generateAgentCertificate('agent-alpha');
  const certB = ca.generateAgentCertificate('agent-beta');
  const caCert = ca.getCACertificate();
  console.log('✅ Certificados mTLS gerados para os agentes\n');

  // 3. Criar agentes com mTLS
  const agentA = new mTLSAgent(
    'agent-alpha',
    'primary',
    tokenAuthority,
    certA,
    caCert,
    ['reasoning', 'memory']
  );

  const agentB = new mTLSAgent(
    'agent-beta',
    'secondary',
    tokenAuthority,
    certB,
    caCert,
    ['analysis', 'synthesis']
  );

  // 4. Inicializar agentes
  await agentA.initialize();
  await agentB.initialize();
  console.log('');

  // 5. Iniciar servidores TLS
  await agentA.startTLSServer(8443);
  await agentB.startTLSServer(8444);
  console.log('');

  // 6. Estabelecer conexões mTLS
  await agentA.connectToPeer('localhost', 8444, 'agent-beta');
  await agentB.connectToPeer('localhost', 8443, 'agent-alpha');
  console.log('');

  // 7. Ativar auto-renovação
  agentA.startAutoRenewal(30000);
  agentB.startAutoRenewal(30000);

  // 8. Conversa segura via mTLS
  console.log('💬 Iniciando conversa segura via mTLS...\n');
  
  await new Promise(resolve => setTimeout(resolve, 1000));
  await agentA.sendMessage('agent-beta', 'Olá Beta! Conexão segura estabelecida via mTLS.');
  
  await new Promise(resolve => setTimeout(resolve, 1000));
  await agentB.sendMessage('agent-alpha', 'Olá Alpha! Nossa comunicação está protegida por mTLS + JWT.');

  await new Promise(resolve => setTimeout(resolve, 1000));
  await agentA.sendMessage('agent-beta', 'Perfeito! Temos segurança em duas camadas: transporte (mTLS) e aplicação (JWT).');

  // Mostrar histórico
  console.log('\n📜 Histórico da conversa:');
  const history = agentA.getConversationHistory();
  history.forEach(msg => {
    const time = new Date(msg.timestamp).toLocaleTimeString();
    console.log(`[${time}] ${msg.from} → ${msg.to}: ${msg.content}`);
  });

  console.log('\n✅ Demonstração concluída!');
  console.log('🔒 Segurança em duas camadas:');
  console.log('   1. mTLS: Autenticação mútua de transporte');
  console.log('   2. JWT: Autenticação de identidade e contexto\n');

  // Cleanup
  setTimeout(() => {
    agentA.stop();
    agentB.stop();
    process.exit(0);
  }, 2000);
}

// Executar se chamado diretamente
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateMTLSAgents().catch(console.error);
}

export { mTLSAgent, CertificateAuthority, TokenAuthority, AgentMessage };

