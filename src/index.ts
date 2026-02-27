/**
 * @vibe2founder/sentinel
 * 
 * Biblioteca de segurança para agentes autônomos de IA
 * Implementa arquitetura Zero-Trust tri-camada:
 * - mTLS para transporte
 * - Signal Protocol (Double Ratchet) para E2EE
 * - DPoP (RFC 9449) para autorização contextual
 * 
 * @package @vibe2founder/sentinel
 * @version 0.1.0
 * @license Apache-2.0
 */

// ============================================================================
// Exportações Públicas
// ============================================================================

// Módulo Criptográfico
export type {
  X25519KeyPair,
  Ed25519KeyPair,
  KeyBundle,
  SignalMessage,
  JWK,
  BloomFilterCRL,
} from './crypto';

export {
  generateX25519KeyPair,
  generateEd25519KeyPair,
  computeDH,
  hkdf,
  kdfRK,
  kdfCK,
  encrypt,
  decrypt,
  secureZero,
  secureZeroMultiple,
  
  // X3DH
  X3DHKeyBundle,
  performX3DHAsInitiator,
  
  // Double Ratchet
  DoubleRatchet,
  
  // JWK Thumbprint (RFC 7638)
  publicKeyToJWK,
  computeJWKThumbprint,
  
  // Bloom Filter para CRL
  BloomFilter,
  createBloomFilterForCRL,
  isRevoked,
} from './crypto';

// Módulo de Autenticação
export type {
  JWTPayload,
  JWTHeaderParameters,
  JWTVerifyResult,
  JWTVerifyOptions,
  
  DPoPAlgorithm,
  DPoPKeyPair,
  DPoPProof,
  DPoPProofPayload,
  DPoPVerificationResult,
  DPoPServerConfig,
  DPoPHttpMethod,

  TokenData,
  TokenManagerConfig,
  
  CircuitBreakerConfig,
  CircuitState,
} from './auth';

export {
  DPoPHttpMethods,
  
  // JWT
  SignJWT,
  jwtVerify,
  generateKeyPair,
  
  // DPoP
  generateDPoPKeyPair,
  computeAccessTokenHash,
  createDPoPProof,
  verifyDPoPProof,
  createDPoPAuthHeader,
  parseDPoPAuthHeader,
  
  // Nonce
  generateNonce,
  createNonceManager,
  issueNonce,
  validateNonce,
  
  // Server
  DPoPServer,
  
  CircuitOpenError,
} from './auth';

// ============================================================================
// Agent Classes (Alto Nível)
// ============================================================================

import { EventEmitter } from 'node:events';
import {
  DoubleRatchet,
  X3DHKeyBundle,
  performX3DHAsInitiator,
  generateX25519KeyPair,
  type KeyBundle,
  type SignalMessage,
  computeJWKThumbprint,
  publicKeyToJWK,
  secureZero,
  generateEd25519KeyPair,
  computeDH,
  hkdf,
  encrypt,
  decrypt,
} from './crypto';
import {
  SignJWT,
  jwtVerify,
  generateKeyPair as generateEdDSAKeyPair,
  generateDPoPKeyPair,
  createDPoPProof,
  verifyDPoPProof,
  computeAccessTokenHash,
  type DPoPKeyPair,
} from './auth';
import * as crypto from 'node:crypto';
import { type AgentId, type ConversationId, AgentIdStamp, ConversationIdStamp } from './types/index';
import { Audit } from './utils/decorators';

// ============================================================================
// Token Authority
// ============================================================================

export class TokenAuthority {
  private privateKey: crypto.KeyObject;
  public publicKey: crypto.KeyObject;
  private issuer = 'urn:agentic-system:authority';
  private audience = 'urn:agentic-system:agents';

  constructor() {
    const keys = generateEdDSAKeyPair() as { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
    this.privateKey = keys.privateKey;
    this.publicKey = keys.publicKey;
  }

  @Audit
  async issueAgentToken(
    agentId: AgentId,
    conversationId: ConversationId,
    capabilities: string[] = []
  ): Promise<string> {
    return await new SignJWT({
      agentId,
      conversationId,
      capabilities,
      encryptionProtocol: 'signal-e2ee',
      issuedAt: Date.now(),
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setSubject(agentId)
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }

  async verifyToken(token: string): Promise<any> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: this.issuer,
      audience: this.audience,
    });
    return payload;
  }
}

// ============================================================================
// Agente com Signal E2EE
// ============================================================================

export class SignalE2EEAgent extends EventEmitter {
  readonly agentId: AgentId;
  private keyBundle: X3DHKeyBundle;
  private sessions: Map<string, DoubleRatchet> = new Map();
  private messageHistory: SignalMessage[] = [];
  private token: string | null = null;
  private authority: TokenAuthority;
  private conversationId: ConversationId;
  private peerPublicBundles: Map<string, KeyBundle> = new Map();
  private identityKey: ReturnType<typeof generateX25519KeyPair>;
  private dpopKeyPair: DPoPKeyPair;

  constructor(
    agentId: AgentId,
    authority: TokenAuthority,
    _capabilities: string[] = []
  ) {
    super();
    this.agentId = agentId;
    this.authority = authority;
    this.keyBundle = new X3DHKeyBundle();
    this.identityKey = generateX25519KeyPair();
    this.conversationId = ConversationIdStamp.of(`conv-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`);
    this.dpopKeyPair = generateDPoPKeyPair('EdDSA');
  }

  @Audit
  async initialize(): Promise<void> {
    this.token = await this.authority.issueAgentToken(
      AgentIdStamp.of(this.agentId),
      this.conversationId
    );
    console.log(`🔐 [${this.agentId}] Agente Signal E2EE inicializado`);
  }

  getPublicKeyBundle(): KeyBundle {
    return this.keyBundle.getPublicBundle();
  }

  registerPeerBundle(peerId: string, bundle: KeyBundle): void {
    this.peerPublicBundles.set(peerId, bundle);
    console.log(`📋 [${this.agentId}] Bundle de ${peerId} registrado`);
  }

  async establishSession(peerId: string): Promise<void> {
    const peerBundle = this.peerPublicBundles.get(peerId);
    if (!peerBundle) {
      throw new Error(`Bundle de ${peerId} não encontrado`);
    }

    const ephemeralKey = generateX25519KeyPair();
    const sharedSecret = performX3DHAsInitiator(
      this.identityKey,
      ephemeralKey,
      peerBundle
    );

    const ratchet = new DoubleRatchet();
    ratchet.initializeAsAlice(sharedSecret, peerBundle.signedPreKey);

    this.sessions.set(peerId, ratchet);

    secureZero(ephemeralKey.privateKey);
    console.log(`🔗 [${this.agentId}] Sessão E2EE estabelecida com ${peerId}`);
  }

  async acceptSession(
    peerId: string,
    senderIdentityKey: Uint8Array,
    senderEphemeralKey: Uint8Array
  ): Promise<Uint8Array> {
    const sharedSecret = this.keyBundle.performX3DHAsReceiver(
      senderEphemeralKey,
      senderIdentityKey,
      true
    );

    const ratchet = new DoubleRatchet();
    ratchet.initializeAsBob(sharedSecret);

    this.sessions.set(peerId, ratchet);
    console.log(`🔗 [${this.agentId}] Sessão E2EE aceita de ${peerId}`);

    return ratchet.getPublicKey();
  }

  @Audit
  async sendMessage(peerId: string, content: string): Promise<SignalMessage> {
    const session = this.sessions.get(peerId);
    if (!session) {
      throw new Error(`Sessão com ${peerId} não estabelecida`);
    }

    const { header, ciphertext, nonce } = session.ratchetEncrypt(content);

    const message: SignalMessage = {
      from: this.agentId,
      to: peerId,
      messageId: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      header,
      ciphertext: Buffer.from(ciphertext).toString('hex'),
      nonce: Buffer.from(nonce).toString('hex'),
    };
    if (this.token) {
      message.jwt = this.token;
    }

    this.messageHistory.push(message);
    console.log(`📤 [${this.agentId}] → [${peerId}] (E2EE): [${content.length} chars encrypted]`);

    return message;
  }

  @Audit
  async receiveMessage(message: SignalMessage): Promise<string> {
    if (message.jwt) {
      try {
        await this.authority.verifyToken(message.jwt);
      } catch (error) {
        console.warn(`⚠️ [${this.agentId}] JWT inválido de ${message.from}`);
      }
    }

    const session = this.sessions.get(message.from);
    if (!session) {
      throw new Error(`Sessão com ${message.from} não encontrada`);
    }

    const ciphertext = Buffer.from(message.ciphertext, 'hex');
    const nonce = Buffer.from(message.nonce, 'hex');

    const plaintext = session.ratchetDecrypt(message.header, ciphertext, nonce);

    this.messageHistory.push(message);
    console.log(`📥 [${this.agentId}] ← [${message.from}] (E2EE): ${plaintext}`);

    this.emit('message', { from: message.from, content: plaintext, message });

    return plaintext;
  }

  /**
   * Cria DPoP Proof com Session Context Latching
   */
  async createDPoPProof(
    method: string,
    url: string,
    accessToken?: string
  ): Promise<ReturnType<typeof createDPoPProof>> {
    const opts: any = {
      method: method as any,
      url,
      signalIdentityKey: this.identityKey.publicKey,
    };
    if (accessToken) {
      opts.accessToken = accessToken;
    }
    return await createDPoPProof(this.dpopKeyPair, opts);
  }

  /**
   * Retorna JWK Thumbprint da identidade Signal para session binding
   */
  getIdentityThumbprint(): string {
    const jwk = publicKeyToJWK(this.identityKey.publicKey, 'X25519');
    return computeJWKThumbprint(jwk);
  }

  getMessageHistory(): SignalMessage[] {
    return [...this.messageHistory];
  }

  getIdentityPublicKey(): Uint8Array {
    return this.identityKey.publicKey;
  }

  getDPoPPublicKey(): DPoPKeyPair {
    return this.dpopKeyPair;
  }

  destroy(): void {
    this.sessions.forEach(session => session.destroy());
    this.sessions.clear();
    this.keyBundle.destroy();
    secureZero(this.identityKey.privateKey);
  }
}

// ============================================================================
// Schema Validation (Zod-like)
// ============================================================================

export interface SchemaValidator<T> {
  parse(data: unknown): T;
  safeParse(data: unknown): { success: true; data: T } | { success: false; error: Error };
}

/**
 * Criador simples de validadores de schema
 * Em produção, use Zod ou Arktype
 */
export function createValidator<T>(
  schema: Record<string, (value: any) => boolean>,
  typeName: string
): SchemaValidator<T> {
  return {
    parse(data: unknown): T {
      const result = this.safeParse(data);
      if (!result.success) {
        throw result.error;
      }
      return result.data;
    },

    safeParse(data: unknown): { success: true; data: T } | { success: false; error: Error } {
      if (typeof data !== 'object' || data === null) {
        return { success: false, error: new Error(`${typeName} deve ser um objeto`) };
      }

      const obj = data as Record<string, any>;
      
      for (const [key, validator] of Object.entries(schema)) {
        if (!(key in obj)) {
          return { success: false, error: new Error(`Campo "${key}" ausente`) };
        }
        if (!validator(obj[key])) {
          return { success: false, error: new Error(`Campo "${key}" inválido`) };
        }
      }

      return { success: true, data: obj as T };
    },
  };
}

// ============================================================================
// Utility Exports
// ============================================================================

export const CryptoUtils = {
  generateX25519KeyPair,
  generateEd25519KeyPair,
  computeDH,
  hkdf,
  encrypt,
  decrypt,
  secureZero,
};

export const AuthUtils = {
  generateDPoPKeyPair,
  computeAccessTokenHash,
  createDPoPProof,
  verifyDPoPProof,
};

// ============================================================================
// EventSourcing & Observability
// ============================================================================

export type {
  EventEnvelope,
  EventContext,
  EventTimestamp,
  EventOrigin,
  EventSecurity,
  EventSchema,
  EventEnvelopeOptions,
} from './utils/EventEnvelope';

export type {
  EventId,
  AggregateId,
  CorrelationId,
  CausationId,
  EventVersion,
} from './types/index';

export {
  AgentIdStamp,
  ConversationIdStamp,
  EventIdStamp,
  AggregateIdStamp,
  CorrelationIdStamp,
  CausationIdStamp,
  EventVersionStamp,
} from './types/index';

export {
  createEventEnvelope,
  isEventEnvelope,
  getEnvelopePayload,
  getEnvelopeTracking,
} from './utils/EventEnvelope';

export type {
  EventSourcingProxyConfig,
  EventStore,
  EventSourcedMethod,
} from './utils/EventSourcingProxy';

export {
  EventSourcingProxy,
  createEventSourcingProxy,
  InMemoryEventStore,
} from './utils/EventSourcingProxy';

// ============================================================================
// Version
// ============================================================================

export const VERSION = '0.1.0';
export const LIBRARY_NAME = '@vibe2founder/sentinel';
