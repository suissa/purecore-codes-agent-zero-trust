import { A2AOperations, StreamEvent } from "../protocol/operations";
import { Task } from "../core/task";
import { Message, SendMessageRequest } from "../core/message";
import { AgentCard } from "../core/agent-card";
import { SignJWT, jwtVerify } from "../../../src/index";
import * as crypto from 'crypto';
import * as tls from 'tls';
import {
  DPoPKeyPair,
  DPoPProof,
  DPoPServer,
  DPoPHttpMethod,
  generateDPoPKeyPair,
  createDPoPProof,
  verifyDPoPProof,
  createDPoPAuthHeader,
  parseDPoPAuthHeader,
  computeAccessTokenHash,
  DPoPAlgorithm,
} from "../../auth/dpop";
import { DPoPAuthToken, DPoPAuthTokenData } from "../../auth/token/bearer";

/**
 * Canal Ultra-Seguro A2A
 * Implementa múltiplas camadas de segurança:
 * 1. mTLS - Autenticação mútua de transporte
 * 2. JWT - Autenticação de aplicação com EdDSA
 * 3. E2EE - Criptografia end-to-end das mensagens
 */
export class UltraSecureA2AChannel implements A2AOperations {
  private privateKey: crypto.KeyObject;
  private publicKey: crypto.KeyObject;
  private peerPublicKeys: Map<string, crypto.KeyObject> = new Map();
  private tasks: Map<string, Task> = new Map();
  private agentCard: AgentCard;
  
  private dpopKeyPair: DPoPKeyPair;
  private dpopToken: DPoPAuthTokenData | null = null;
  private dpopServer: DPoPServer;
  private dpopAlgorithm: DPoPAlgorithm;
  
  constructor(
    private agentId: string,
    private certificate: { cert: string; key: string },
    private caCert: string,
    keyPair?: { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject },
    options?: {
      dpopAlgorithm?: DPoPAlgorithm;
      nonceTtlSeconds?: number;
    }
  ) {
    if (keyPair) {
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.privateKey = generated.privateKey;
      this.publicKey = generated.publicKey;
    }
    
    this.dpopAlgorithm = options?.dpopAlgorithm || 'ES256';
    this.dpopKeyPair = generateDPoPKeyPair(this.dpopAlgorithm);
    this.dpopServer = new DPoPServer({ nonceTtlSeconds: options?.nonceTtlSeconds });
    
    this.agentCard = AgentCard.make({
      agentId: this.agentId,
      name: `Ultra-Secure Agent ${this.agentId}`,
      description: 'Agent with ultra-secure A2A communication with DPoP',
      protocolVersion: '1.0',
      endpoint: `https://${this.agentId}.a2a.local`,
      capabilities: {
        streaming: true,
        pushNotifications: true,
        supportedContentTypes: ['text/plain', 'application/json', 'application/octet-stream'],
        supportedOperations: [
          'sendMessage',
          'sendStreamingMessage', 
          'getTask',
          'listTasks',
          'cancelTask',
          'subscribeToTask'
        ]
      },
      authentication: {
        type: 'dpop',
        config: {
          algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
          requireAth: true,
          nonceSupported: true
        }
      }
    });
  }

  setDPoPToken(token: string, expiresInMs: number = 3600000): void {
    const createdAt = Date.now();
    const expiresAt = createdAt + expiresInMs;
    
    this.dpopToken = {
      accessToken: token,
      dpopKeyPair: this.dpopKeyPair,
      createdAt,
      expiresAt,
    };
  }

  private async getDPoPProof(
    method: DPoPHttpMethod,
    url: string,
    options?: { nonce?: string }
  ): Promise<DPoPProof> {
    if (!this.dpopToken) {
      throw new Error('DPoP token not set. Call setDPoPToken() first.');
    }

    return await createDPoPProof(this.dpopKeyPair, {
      method,
      url,
      accessToken: this.dpopToken.accessToken,
      nonce: options?.nonce,
    });
  }

  private async createDPoPAuthHeader(
    method: DPoPHttpMethod,
    url: string,
    options?: { nonce?: string }
  ): Promise<string> {
    if (!this.dpopToken) {
      throw new Error('DPoP token not set. Call setDPoPToken() first.');
    }

    const proof = await this.getDPoPProof(method, url, options);
    return createDPoPAuthHeader(this.dpopToken.accessToken, proof.jwt);
  }

  /**
   * Registra chave pública X25519 de um peer para comunicação E2EE
   */
  registerPeerX25519Key(peerId: string, x25519PublicKey: crypto.KeyObject): void {
    this.peerPublicKeys.set(peerId, x25519PublicKey);
  }

  /**
   * Gera par de chaves X25519 para E2EE
   */
  static generateX25519KeyPair(): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
    return crypto.generateKeyPairSync('x25519');
  }

  /**
   * Criptografa dados usando chave pública X25519 do destinatário
   */
  private encryptForPeer(peerId: string, data: string): string {
    const peerPublicKey = this.peerPublicKeys.get(peerId);
    if (!peerPublicKey) {
      throw new Error(`No X25519 public key found for peer: ${peerId}`);
    }

    const ephemeralKeyPair = crypto.generateKeyPairSync('x25519');
    const ephemeralPrivateKey = ephemeralKeyPair.privateKey;
    const ephemeralPublicKey = ephemeralKeyPair.publicKey;

    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeralPrivateKey,
      publicKey: peerPublicKey,
    });

    const symmetricKey = crypto.createHash('sha256')
      .update(sharedSecret)
      .digest();

    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
    cipher.setAAD(Buffer.from(peerId, 'utf8'));
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    const ephemeralPublicKeyPem = ephemeralPublicKey.export({ type: 'spki', format: 'pem' });

    return JSON.stringify({
      encryptedData: encrypted,
      encryptedKey: ephemeralPublicKeyPem,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    });
  }

  /**
   * Descriptografa dados usando chave privada X25519
   */
  private decryptFromPeer(encryptedPayload: string): string {
    const payload = JSON.parse(encryptedPayload);
    
    const ephemeralPublicKeyPem = payload.encryptedKey;
    const ephemeralPublicKey = crypto.createPublicKey(ephemeralPublicKeyPem);
    
    const sharedSecret = crypto.diffieHellman({
      privateKey: this.privateKey,
      publicKey: ephemeralPublicKey,
    });

    const symmetricKey = crypto.createHash('sha256')
      .update(sharedSecret)
      .digest();
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, Buffer.from(payload.iv, 'base64'));
    const authTag = Buffer.from(payload.authTag, 'base64');
    
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(payload.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Cria JWT assinado para autenticação
   */
  private async createAuthToken(peerId?: string): Promise<string> {
    const payload: any = {
      agentId: this.agentId,
      timestamp: Date.now()
    };
    
    if (peerId) {
      payload.audience = peerId;
    }

    return await new SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(`a2a:${this.agentId}`)
      .setExpirationTime('1h')
      .setSubject(this.agentId)
      .sign(this.privateKey);
  }

  /**
   * Verifica JWT de um peer
   */
  private async verifyAuthToken(token: string, peerId: string): Promise<any> {
    const peerPublicKey = this.peerPublicKeys.get(peerId);
    if (!peerPublicKey) {
      throw new Error(`No public key found for peer: ${peerId}`);
    }

    const { payload } = await jwtVerify(token, peerPublicKey, {
      issuer: `a2a:${peerId}`,
      audience: this.agentId
    });

    return payload;
  }

  async sendMessage(request: SendMessageRequest): Promise<Task | Message> {
    const requestData = SendMessageRequest.un(request);
    const message = Message.un(requestData.message);
    
    // Criar nova task
    const taskId = `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const task = Task.make({
      id: taskId,
      status: 'pending',
      contextId: message.contextId,
      messages: [requestData.message]
    });
    
    this.tasks.set(taskId, task);
    
    // Simular processamento assíncrono
    setTimeout(async () => {
      try {
        const updatedTask = Task.updateStatus(task, 'running');
        this.tasks.set(taskId, updatedTask);
        
        // Simular processamento da mensagem
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Criar resposta
        const responseMessage = Message.text(
          'agent',
          `Processed message: "${Message.extractText(requestData.message)}" via ultra-secure channel`,
          { contextId: message.contextId }
        );
        
        const completedTask = Task.addMessage(
          Task.updateStatus(updatedTask, 'completed'),
          Message.un(responseMessage)
        );
        
        this.tasks.set(taskId, completedTask);
      } catch (error) {
        const failedTask = Task.updateStatus(task, 'failed');
        this.tasks.set(taskId, failedTask);
      }
    }, 100);
    
    return task;
  }

  async *sendStreamingMessage(request: SendMessageRequest): AsyncIterable<StreamEvent> {
    const task = await this.sendMessage(request) as Task;
    const taskData = Task.un(task);
    
    // Yield initial task
    yield {
      type: 'task_status_update',
      taskId: taskData.id,
      status: taskData.status,
      timestamp: Date.now()
    };
    
    // Simular updates em tempo real
    let currentTask = task;
    while (!Task.isTerminal(currentTask)) {
      await new Promise(resolve => setTimeout(resolve, 500));
      
      currentTask = this.tasks.get(taskData.id) || currentTask;
      const currentData = Task.un(currentTask);
      
      yield {
        type: 'task_status_update',
        taskId: currentData.id,
        status: currentData.status,
        timestamp: Date.now()
      };
      
      if (currentData.status === 'completed' && currentData.messages.length > 1) {
        // Converter TaskMessage para Message
        const lastTaskMessage = currentData.messages[currentData.messages.length - 1];
        const message = Message.make({
          id: lastTaskMessage.id,
          role: lastTaskMessage.role,
          parts: lastTaskMessage.parts,
          timestamp: lastTaskMessage.timestamp
        });
        
        yield {
          type: 'message',
          message,
          timestamp: Date.now()
        };
      }
    }
  }

  async getTask(taskId: string, options?: any): Promise<Task> {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new Error(`Task not found: ${taskId}`);
    }
    return task;
  }

  async listTasks(options?: any): Promise<any> {
    const tasks = Array.from(this.tasks.values());
    
    return {
      tasks,
      nextPageToken: '',
      pageSize: tasks.length,
      totalSize: tasks.length
    };
  }

  async cancelTask(taskId: string): Promise<Task> {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new Error(`Task not found: ${taskId}`);
    }
    
    if (!Task.isCancelable(task)) {
      throw new Error(`Task cannot be cancelled: ${taskId}`);
    }
    
    const cancelledTask = Task.updateStatus(task, 'cancelled');
    this.tasks.set(taskId, cancelledTask);
    
    return cancelledTask;
  }

  async *subscribeToTask(taskId: string): AsyncIterable<StreamEvent> {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new Error(`Task not found: ${taskId}`);
    }
    
    // Yield current state
    const taskData = Task.un(task);
    yield {
      type: 'task_status_update',
      taskId: taskData.id,
      status: taskData.status,
      timestamp: Date.now()
    };
    
    // Monitor for changes
    let currentTask = task;
    while (!Task.isTerminal(currentTask)) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const updatedTask = this.tasks.get(taskId);
      if (updatedTask && Task.un(updatedTask).updatedAt > Task.un(currentTask).updatedAt) {
        currentTask = updatedTask;
        const currentData = Task.un(currentTask);
        
        yield {
          type: 'task_status_update',
          taskId: currentData.id,
          status: currentData.status,
          timestamp: Date.now()
        };
      }
    }
  }

  async getAgentCard(): Promise<AgentCard> {
    return this.agentCard;
  }

  /**
   * Estabelece conexão mTLS com outro agente
   */
  async connectToPeer(host: string, port: number, peerId: string): Promise<tls.TLSSocket> {
    const options: tls.ConnectionOptions = {
      host,
      port,
      cert: this.certificate.cert,
      key: this.certificate.key,
      ca: [this.caCert],
      requestCert: true,
      rejectUnauthorized: true,
      checkServerIdentity: (hostname, cert) => {
        // Verificar se o certificado pertence ao peer esperado
        const subject = cert.subject as any;
        if (subject.CN !== peerId) {
          throw new Error(`Certificate CN mismatch: expected ${peerId}, got ${subject.CN}`);
        }
        return undefined;
      }
    };

    return new Promise((resolve, reject) => {
      const socket = tls.connect(options, () => {
        console.log(`🔒 [${this.agentId}] Conexão mTLS estabelecida com ${peerId}`);
        resolve(socket);
      });

      socket.on('error', reject);
    });
  }

  /**
   * Inicia servidor mTLS para receber conexões
   */
  async startTLSServer(port: number): Promise<tls.Server> {
    const options: tls.TlsOptions = {
      cert: this.certificate.cert,
      key: this.certificate.key,
      ca: [this.caCert],
      requestCert: true,
      rejectUnauthorized: true
    };

    const server = tls.createServer(options, (socket) => {
      const cert = socket.getPeerCertificate();
      const peerId = (cert.subject as any).CN;
      
      console.log(`🔒 [${this.agentId}] Conexão mTLS recebida de ${peerId}`);
      
      socket.on('data', async (data) => {
        try {
          const message = JSON.parse(data.toString());
          
          // Verificar JWT
          await this.verifyAuthToken(message.token, peerId);
          
          // Descriptografar payload se necessário
          let payload = message.payload;
          if (message.encrypted) {
            payload = this.decryptFromPeer(payload);
          }
          
          console.log(`📥 [${this.agentId}] ← [${peerId}] (Ultra-Secure): ${payload}`);
          
          // Enviar resposta
          const responsePayload = `Echo: ${payload}`;
          const authToken = await this.createAuthToken(peerId);
          
          const response = {
            token: authToken,
            payload: responsePayload,
            encrypted: false
          };
          
          socket.write(JSON.stringify(response));
        } catch (error) {
          console.error(`❌ [${this.agentId}] Erro ao processar mensagem de ${peerId}:`, error);
        }
      });
    });

    return new Promise((resolve, reject) => {
      server.listen(port, () => {
        console.log(`🔒 [${this.agentId}] Servidor Ultra-Secure A2A iniciado na porta ${port}`);
        resolve(server);
      });
      
      server.on('error', reject);
    });
  }

  /**
   * Envia mensagem ultra-segura para um peer com DPoP
   */
  async sendSecureMessage(
    peerId: string,
    content: string,
    socket: tls.TLSSocket,
    options?: {
      encrypt?: boolean;
      useDPoP?: boolean;
      method?: DPoPHttpMethod;
      url?: string;
    }
  ): Promise<void> {
    const useDPoP = options?.useDPoP ?? false;
    let payload = content;

    if (options?.encrypt) {
      payload = this.encryptForPeer(peerId, content);
    }

    const message: any = {
      payload,
      encrypted: options?.encrypt ?? false,
    };

    if (useDPoP && this.dpopToken) {
      const method = options?.method || 'POST';
      const url = options?.url || `https://${peerId}.a2a.local/message`;
      const authHeader = await this.createDPoPAuthHeader(method, url);
      message.dpop = authHeader;
    } else {
      const authToken = await this.createAuthToken(peerId);
      message.token = authToken;
    }

    socket.write(JSON.stringify(message));
    console.log(`📤 [${this.agentId}] → [${peerId}] (Ultra-Secure): ${content}`);
  }

  /**
   * Verifica DPoP proof de uma mensagem recebida
   */
  async verifyIncomingDPoP(authHeader: string, method: string, url: string): Promise<boolean> {
    const result = await this.dpopServer.verifyDPoPAuthHeader(authHeader, {
      requiredMethod: method as DPoPHttpMethod,
      requiredUrl: url,
      audience: this.agentId,
    });

    return result.valid;
  }

  /**
   * Gera nonce para DPoP
   */
  async generateNonce(clientId: string): Promise<string> {
    return await this.dpopServer.issueNonce(clientId);
  }
}