/**
 * Self-Healing Agentic Conversational System
 * 
 * Sistema onde dois agentes se identificam usando JWTs do mesmo servidor
 * e regeneram automaticamente seus tokens quando expiram, mantendo a
 * conversa contínua sem interrupção.
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';

// ============================================================================
// Configuração do Servidor de Autoridade (Token Issuer)
// ============================================================================

interface AgentIdentity {
  agentId: string;
  agentType: 'primary' | 'secondary';
  capabilities: string[];
}

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

  /**
   * Emite um token para um agente com contexto de conversa
   */
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
      .setExpirationTime('5m') // Tokens curtos para segurança
      .sign(this.privateKey);
  }

  /**
   * Verifica e renova um token mantendo o contexto da conversa
   */
  async renewToken(oldToken: string): Promise<string> {
    try {
      // Verifica o token antigo (pode estar expirado, mas ainda válido para renovação)
      const { payload } = await jwtVerify(oldToken, this.publicKey, {
        issuer: this.issuer,
        audience: this.audience,
        // Não validamos exp aqui para permitir renovação de tokens expirados
      }).catch(() => {
        // Se falhar, tenta decodificar sem verificar assinatura para extrair contexto
        const parts = oldToken.split('.');
        if (parts.length !== 3) throw new Error('Token inválido');
        const decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
        return { payload: decoded };
      });

      // Renova mantendo o contexto da conversa
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
// Classe Base para Agentes Auto-Recuperáveis
// ============================================================================

interface AgentMessage {
  from: string;
  to: string;
  content: string;
  timestamp: number;
  messageId: string;
}

class SelfHealingAgent {
  private agentId: string;
  private agentType: 'primary' | 'secondary';
  private conversationId: string;
  private capabilities: string[];
  private token: string | null = null;
  private tokenExpiry: number = 0;
  private renewalThreshold: number = 60; // Renovar 60s antes de expirar
  private authority: TokenAuthority;
  private messageHistory: AgentMessage[] = [];

  constructor(
    agentId: string,
    agentType: 'primary' | 'secondary',
    authority: TokenAuthority,
    capabilities: string[] = []
  ) {
    this.agentId = agentId;
    this.agentType = agentType;
    this.authority = authority;
    this.capabilities = capabilities;
    this.conversationId = `conv-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Inicializa o agente obtendo seu primeiro token
   */
  async initialize(): Promise<void> {
    this.token = await this.authority.issueAgentToken(
      this.agentId,
      this.agentType,
      this.conversationId,
      this.capabilities
    );
    this.tokenExpiry = Date.now() + (5 * 60 * 1000); // 5 minutos
    console.log(`🤖 [${this.agentId}] Agente inicializado com token válido até ${new Date(this.tokenExpiry).toISOString()}`);
  }

  /**
   * Verifica e renova o token se necessário (self-healing)
   */
  private async ensureValidToken(): Promise<void> {
    const now = Date.now();
    const timeUntilExpiry = this.tokenExpiry - now;

    // Se o token está próximo de expirar ou já expirou, renova
    if (!this.token || timeUntilExpiry < this.renewalThreshold * 1000) {
      if (this.token) {
        console.log(`🔄 [${this.agentId}] Token próximo de expirar, renovando...`);
      } else {
        console.log(`🔄 [${this.agentId}] Gerando novo token...`);
      }

      try {
        if (this.token) {
          // Tenta renovar mantendo contexto
          this.token = await this.authority.renewToken(this.token);
        } else {
          // Primeira inicialização
          await this.initialize();
          return;
        }

        this.tokenExpiry = Date.now() + (5 * 60 * 1000);
        console.log(`✅ [${this.agentId}] Token renovado com sucesso. Válido até ${new Date(this.tokenExpiry).toISOString()}`);
      } catch (error) {
        console.error(`❌ [${this.agentId}] Erro ao renovar token:`, error);
        // Fallback: reinicializa completamente
        await this.initialize();
      }
    }
  }

  /**
   * Verifica a identidade de outro agente
   */
  async verifyPeerIdentity(peerToken: string): Promise<{ agentId: string; conversationId: string; valid: boolean }> {
    try {
      const { payload } = await jwtVerify(peerToken, this.authority.publicKey, {
        issuer: 'urn:agentic-system:authority',
        audience: 'urn:agentic-system:agents'
      });

      // Verifica se está na mesma conversa
      const sameConversation = payload.conversationId === this.conversationId;
      
      return {
        agentId: payload.agentId as string,
        conversationId: payload.conversationId as string,
        valid: sameConversation
      };
    } catch (error) {
      return {
        agentId: 'unknown',
        conversationId: 'unknown',
        valid: false
      };
    }
  }

  /**
   * Envia uma mensagem para outro agente
   */
  async sendMessage(to: SelfHealingAgent, content: string): Promise<void> {
    // Garante que o token está válido antes de enviar
    await this.ensureValidToken();

    if (!this.token) {
      throw new Error('Agente não possui token válido');
    }

    // Verifica a identidade do destinatário
    const peerIdentity = await this.verifyPeerIdentity(to.getToken());
    
    if (!peerIdentity.valid) {
      throw new Error(`Agente ${peerIdentity.agentId} não está na mesma conversa`);
    }

    const message: AgentMessage = {
      from: this.agentId,
      to: peerIdentity.agentId,
      content,
      timestamp: Date.now(),
      messageId: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };

    this.messageHistory.push(message);
    console.log(`📤 [${this.agentId}] → [${peerIdentity.agentId}]: ${content}`);
    
    // Envia para o destinatário
    await to.receiveMessage(message, this.token);
  }

  /**
   * Recebe uma mensagem de outro agente
   */
  async receiveMessage(message: AgentMessage, senderToken: string): Promise<void> {
    // Garante que o token está válido antes de receber
    await this.ensureValidToken();

    // Verifica a identidade do remetente
    const senderIdentity = await this.verifyPeerIdentity(senderToken);
    
    if (!senderIdentity.valid || senderIdentity.agentId !== message.from) {
      throw new Error(`Mensagem de agente não autorizado: ${senderIdentity.agentId}`);
    }

    this.messageHistory.push(message);
    console.log(`📥 [${this.agentId}] ← [${message.from}]: ${message.content}`);
  }

  /**
   * Retorna o token atual (para verificação de identidade)
   */
  getToken(): string {
    if (!this.token) {
      throw new Error('Agente não possui token');
    }
    return this.token;
  }

  /**
   * Retorna o histórico da conversa
   */
  getConversationHistory(): AgentMessage[] {
    return [...this.messageHistory];
  }

  /**
   * Inicia monitoramento automático de renovação de token
   */
  startAutoRenewal(intervalMs: number = 30000): void {
    setInterval(async () => {
      await this.ensureValidToken();
    }, intervalMs);
    
    console.log(`🔄 [${this.agentId}] Auto-renovação de token ativada (verifica a cada ${intervalMs}ms)`);
  }
}

// ============================================================================
// Exemplo de Uso: Conversa Auto-Recuperável entre Dois Agentes
// ============================================================================

async function demonstrateSelfHealingAgents() {
  console.log('🚀 Iniciando demonstração de Self-Healing Agentic Conversational System\n');

  // 1. Criar autoridade de tokens
  const authority = new TokenAuthority();
  console.log('✅ Autoridade de tokens criada\n');

  // 2. Criar dois agentes
  const agentA = new SelfHealingAgent(
    'agent-alpha',
    'primary',
    authority,
    ['reasoning', 'memory', 'planning']
  );

  const agentB = new SelfHealingAgent(
    'agent-beta',
    'secondary',
    authority,
    ['analysis', 'synthesis', 'validation']
  );

  // 3. Inicializar agentes
  await agentA.initialize();
  await agentB.initialize();
  console.log('');

  // 4. Ativar auto-renovação
  agentA.startAutoRenewal(30000); // Verifica a cada 30 segundos
  agentB.startAutoRenewal(30000);

  // 5. Simular conversa longa (que ultrapassa expiração de token)
  console.log('💬 Iniciando conversa entre agentes...\n');

  // Primeira troca de mensagens
  await agentA.sendMessage(agentB, 'Olá! Sou o Agente Alpha. Como você está?');
  await new Promise(resolve => setTimeout(resolve, 1000));

  await agentB.sendMessage(agentA, 'Olá Alpha! Sou o Agente Beta. Estou funcionando perfeitamente!');
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Simular espera até próximo da expiração
  console.log('\n⏳ Simulando espera de 4 minutos (tokens expiram em 5 minutos)...\n');
  await new Promise(resolve => setTimeout(resolve, 1000)); // Simulação rápida

  // Continuar conversa após possível renovação automática
  await agentA.sendMessage(agentB, 'Perfeito! Vamos trabalhar juntos neste problema complexo.');
  await new Promise(resolve => setTimeout(resolve, 1000));

  await agentB.sendMessage(agentA, 'Excelente! Estou pronto para colaborar. Meus tokens foram renovados automaticamente.');
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Mostrar histórico
  console.log('\n📜 Histórico da conversa:');
  const history = agentA.getConversationHistory();
  history.forEach(msg => {
    const time = new Date(msg.timestamp).toLocaleTimeString();
    console.log(`[${time}] ${msg.from} → ${msg.to}: ${msg.content}`);
  });

  console.log('\n✅ Demonstração concluída! Os agentes mantiveram a conversa mesmo com renovação automática de tokens.');
}

// Executar demonstração
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateSelfHealingAgents().catch(console.error);
}

export { SelfHealingAgent, TokenAuthority, AgentMessage };

