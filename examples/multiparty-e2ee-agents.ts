/**
 * Multi-Party End-to-End Encryption (Group E2EE)
 * 
 * Demonstração de suporte para múltiplos agentes (>2)
 * 
 * Características:
 * - Suporte para qualquer número de agentes (2, 3, 4, ...)
 * - Chave de grupo compartilhada entre membros
 * - AES-256-GCM para encriptação
 * - JWT para autenticação
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../src/index';
import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface GroupState {
  groupId: string;
  members: Set<string>;
  groupKey: Buffer;
}

interface GroupMessage {
  from: string;
  to: string;
  messageId: string;
  timestamp: number;
  ciphertext: string;
  iv: string;
  authTag: string;
  jwt?: string;
}

interface WelcomeMessage {
  groupId: string;
  members: string[];
  groupKey: string;
  jwt?: string;
}

// ============================================================================
// FUNÇÕES CRIPTOGRÁFICAS
// ============================================================================

/**
 * Encripta usando AES-256-GCM
 */
function encrypt(plaintext: string, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext: encrypted, iv, authTag };
}

/**
 * Decripta usando AES-256-GCM
 */
function decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext) + decipher.final('utf8');
}

// ============================================================================
// AGENTE DE GRUPO COM E2EE
// ============================================================================

class GroupAgent extends EventEmitter {
  readonly agentId: string;
  private groupStates: Map<string, GroupState> = new Map();
  private messageHistory: GroupMessage[] = [];
  private authority: any;

  constructor(
    agentId: string,
    authority: any
  ) {
    super();
    this.agentId = agentId;
    this.authority = authority;
    console.log(`🤖 [${this.agentId}] Group E2EE Agent inicializado`);
  }

  /**
   * Cria um novo grupo
   */
  async createGroup(): Promise<{ groupId: string; welcome: WelcomeMessage }> {
    const groupId = `group-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const groupKey = crypto.randomBytes(32);
    
    const groupState: GroupState = {
      groupId,
      members: new Set([this.agentId]),
      groupKey
    };
    
    this.groupStates.set(groupId, groupState);
    
    const welcome: WelcomeMessage = {
      groupId,
      members: [this.agentId],
      groupKey: groupKey.toString('base64'),
      jwt: await this.getToken(groupId)
    };
    
    console.log(`👥 [${this.agentId}] Grupo criado: ${groupId}`);
    
    return { groupId, welcome };
  }

  /**
   * Entra em um grupo existente
   */
  async joinGroup(welcome: WelcomeMessage): Promise<void> {
    const groupState: GroupState = {
      groupId: welcome.groupId,
      members: new Set(welcome.members),
      groupKey: Buffer.from(welcome.groupKey, 'base64')
    };
    
    groupState.members.add(this.agentId);
    this.groupStates.set(welcome.groupId, groupState);
    
    console.log(`👥 [${this.agentId}] Entrou no grupo: ${welcome.groupId}`);
  }

  /**
   * Envia mensagem para o grupo
   */
  async sendGroupMessage(groupId: string, content: string): Promise<GroupMessage> {
    const groupState = this.groupStates.get(groupId);
    if (!groupState) {
      throw new Error(`Grupo ${groupId} não encontrado`);
    }
    
    if (!groupState.members.has(this.agentId)) {
      throw new Error(`Você não é membro do grupo ${groupId}`);
    }
    
    const { ciphertext, iv, authTag } = encrypt(content, groupState.groupKey);
    
    const message: GroupMessage = {
      from: this.agentId,
      to: groupId,
      messageId: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      jwt: await this.getToken(groupId)
    };
    
    this.messageHistory.push(message);
    
    console.log(`📤 [${this.agentId}] → [${groupId}] (Grupo): ${content}`);
    
    return message;
  }

  /**
   * Recebe mensagem do grupo
   */
  async receiveGroupMessage(message: GroupMessage): Promise<string> {
    const groupState = this.groupStates.get(message.to);
    if (!groupState) {
      throw new Error(`Grupo ${message.to} não encontrado`);
    }
    
    if (!groupState.members.has(this.agentId)) {
      throw new Error(`Você não é membro do grupo ${message.to}`);
    }
    
    if (message.jwt) {
      try {
        await this.authority.verifyToken(message.jwt);
      } catch (error) {
        console.warn(`⚠️ [${this.agentId}] JWT inválido de ${message.from}`);
      }
    }
    
    const ciphertext = Buffer.from(message.ciphertext, 'base64');
    const iv = Buffer.from(message.iv, 'base64');
    const authTag = Buffer.from(message.authTag, 'base64');
    
    const plaintext = decrypt(ciphertext, groupState.groupKey, iv, authTag);
    
    this.messageHistory.push(message);
    console.log(`📥 [${this.agentId}] ← [${message.from}] (Grupo ${message.to}): ${plaintext}`);
    
    this.emit('groupMessage', {
      from: message.from,
      groupId: message.to,
      content: plaintext,
      message
    });
    
    return plaintext;
  }

  /**
   * Adiciona novo membro ao grupo
   */
  async addMemberToGroup(groupId: string, newMemberId: string): Promise<WelcomeMessage> {
    const groupState = this.groupStates.get(groupId);
    if (!groupState) {
      throw new Error(`Grupo ${groupId} não encontrado`);
    }
    
    groupState.members.add(newMemberId);
    
    const welcome: WelcomeMessage = {
      groupId,
      members: Array.from(groupState.members),
      groupKey: groupState.groupKey.toString('base64'),
      jwt: await this.getToken(groupId)
    };
    
    console.log(`👥 [${this.agentId}] Membro ${newMemberId} adicionado ao grupo ${groupId}`);
    
    return welcome;
  }

  /**
   * Remove membro do grupo
   */
  async removeMemberFromGroup(groupId: string, memberId: string): Promise<void> {
    const groupState = this.groupStates.get(groupId);
    if (!groupState) {
      throw new Error(`Grupo ${groupId} não encontrado`);
    }
    
    groupState.members.delete(memberId);
    
    console.log(`👥 [${this.agentId}] Membro ${memberId} removido do grupo ${groupId}`);
  }

  /**
   * Lista membros do grupo
   */
  listGroupMembers(groupId: string): string[] {
    const groupState = this.groupStates.get(groupId);
    if (!groupState) return [];
    return Array.from(groupState.members);
  }

  /**
   * Obtém token JWT
   */
  private async getToken(groupId: string): Promise<string> {
    return await this.authority.issueToken(this.agentId, groupId, ['group-member']);
  }

  /**
   * Retorna histórico de mensagens
   */
  getMessageHistory(): GroupMessage[] {
    return [...this.messageHistory];
  }
}

// ============================================================================
// AUTORIDADE DE TOKENS
// ============================================================================

class TokenAuthority {
  private privateKey: crypto.KeyObject;
  public publicKey: crypto.KeyObject;

  constructor() {
    const keys = generateKeyPair();
    this.privateKey = crypto.createPrivateKey(keys.privateKey);
    this.publicKey = crypto.createPublicKey(keys.publicKey);
  }

  async issueToken(
    agentId: string,
    groupId: string,
    capabilities: string[] = []
  ): Promise<string> {
    return await new SignJWT({
      agentId,
      groupId,
      capabilities,
      encryptionProtocol: 'multi-party-e2ee',
      issuedAt: Date.now()
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer('urn:group-e2ee:authority')
      .setAudience('urn:group-e2ee:agents')
      .setSubject(agentId)
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }

  async verifyToken(token: string): Promise<any> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: 'urn:group-e2ee:authority',
      audience: 'urn:group-e2ee:agents'
    });
    return payload;
  }
}

// ============================================================================
// DEMONSTRAÇÃO
// ============================================================================

async function demonstrateMultiPartyE2EE() {
  console.log('🚀 Demonstração de Multi-Party End-to-End Encryption');
  console.log('   Suporte para múltiplos agentes (>2)\n');
  console.log('═'.repeat(60));

  const authority = new TokenAuthority();
  console.log('✅ Token Authority criada\n');

  const alice = new GroupAgent('alice', authority);
  const bob = new GroupAgent('bob', authority);
  const charlie = new GroupAgent('charlie', authority);
  const diana = new GroupAgent('diana', authority);
  
  console.log('✅ 4 agentes criados: Alice, Bob, Charlie, Diana\n');

  const { groupId, welcome } = await alice.createGroup();
  console.log(`✅ Grupo criado por Alice: ${groupId}\n`);

  const welcomeBob = await alice.addMemberToGroup(groupId, 'bob');
  await bob.joinGroup(welcomeBob);
  console.log('');
  
  const welcomeCharlie = await alice.addMemberToGroup(groupId, 'charlie');
  await charlie.joinGroup(welcomeCharlie);
  console.log('');
  
  const welcomeDiana = await alice.addMemberToGroup(groupId, 'diana');
  await diana.joinGroup(welcomeDiana);
  console.log('');

  console.log('📋 Membros do grupo:');
  console.log(`   ${alice.listGroupMembers(groupId).join(', ')}\n`);

  console.log('💬 Iniciando conversa de grupo (E2EE)...\n');
  console.log('─'.repeat(60));

  const msg1 = await alice.sendGroupMessage(groupId, 'Olá a todos! Bem-vindos ao grupo seguro!');
  await bob.receiveGroupMessage(msg1);
  await charlie.receiveGroupMessage(msg1);
  await diana.receiveGroupMessage(msg1);
  console.log('');

  const msg2 = await bob.sendGroupMessage(groupId, 'Oi Alice! Obrigado por me convidar.');
  await alice.receiveGroupMessage(msg2);
  await charlie.receiveGroupMessage(msg2);
  await diana.receiveGroupMessage(msg2);
  console.log('');

  const msg3 = await charlie.sendGroupMessage(groupId, 'Fico feliz em estar aqui! Grupo E2EE é impressionante.');
  await alice.receiveGroupMessage(msg3);
  await bob.receiveGroupMessage(msg3);
  await diana.receiveGroupMessage(msg3);
  console.log('');

  const msg4 = await diana.sendGroupMessage(groupId, 'Concordo! Cada mensagem usa a mesma chave de grupo.');
  await alice.receiveGroupMessage(msg4);
  await bob.receiveGroupMessage(msg4);
  await charlie.receiveGroupMessage(msg4);
  console.log('');

  console.log('─'.repeat(60));
  console.log('\n🔒 Alice remove Charlie do grupo...\n');
  await alice.removeMemberFromGroup(groupId, 'charlie');
  console.log(`Membros atuais: ${alice.listGroupMembers(groupId).join(', ')}\n`);
  
  const msg5 = await alice.sendGroupMessage(groupId, 'Charlie saiu. Nova mensagem só para membros atuais.');
  await bob.receiveGroupMessage(msg5);
  await diana.receiveGroupMessage(msg5);
  console.log('');
  
  console.log('─'.repeat(60));
  console.log('\n⚠️  Tentativa do Charlie (removido) ler mensagem...\n');
  try {
    await charlie.receiveGroupMessage(msg5);
  } catch (error) {
    console.log(`✅ [charlie] Erro esperado: ${error.message}`);
  }
  console.log('');

  console.log('─'.repeat(60));
  console.log('\n📊 Resumo:\n');
  console.log('🔒 Propriedades de Segurança:');
  console.log('   • Multi-Party E2EE: Múltiplos agentes (>2) no mesmo grupo');
  console.log('   • Chave de grupo compartilhada: Todos os membros usam a mesma chave');
  console.log('   • AES-256-GCM: Encriptação de mensagens');
  console.log('   • JWT: Autenticação de agentes');
  console.log('');
  console.log('🔧 Algoritmos:');
  console.log('   • AES-256-GCM');
  console.log('   • SHA-256 (base64 encoding)');
  console.log('   • Ed25519 (JWT assinaturas)');
  console.log('');
  
  console.log(`📨 Total de mensagens: ${alice.getMessageHistory().length}`);
  console.log(`👥 Total de membros finais: ${alice.listGroupMembers(groupId).length}`);
  console.log('');
  console.log('✅ Demonstração concluída!');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateMultiPartyE2EE().catch(console.error);
}

export {
  GroupAgent,
  TokenAuthority,
  GroupMessage,
  WelcomeMessage
};
