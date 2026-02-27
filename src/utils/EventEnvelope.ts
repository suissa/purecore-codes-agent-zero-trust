/**
 * EventEnvelope - Envelope universal para rastreabilidade e observabilidade
 * 
 * Este envelope encapsula qualquer payload de evento com metadata necessária
 * para auditoria, tracking e evidence chain, sem exigir um schema rígido.
 * 
 * @module EventEnvelope
 */

import {
  type AgentId,
  type ConversationId,
  type EventId,
  type AggregateId,
  type CorrelationId,
  type CausationId,
  type EventVersion,
  type TraceId,
  type SpanId,
  EventIdStamp,
  AggregateIdStamp,
  CorrelationIdStamp,
  CausationIdStamp,
  EventVersionStamp,
  TraceIdStamp,
  SpanIdStamp,
  AgentIdStamp,
  ConversationIdStamp,
} from '../types/index';

// ============================================================================
// Metadata de Rastreabilidade
// ============================================================================

/**
 * Contexto de execução do evento
 */
export interface EventContext {
  /** ID do agente que originou o evento */
  agentId: AgentId;
  
  /** ID da conversa/sessão (para correlacionar eventos relacionados) */
  conversationId?: ConversationId;
  
  /** ID do tenant (para sistemas multi-tenant) */
  tenantId?: string;
  
  /** ID do trace distribuído (W3C Trace Context) */
  traceId: TraceId;
  
  /** ID do span (para observabilidade distribuída) */
  spanId: SpanId;
  
  /** IDs de eventos parent (para causalidade) */
  parentEventIds?: string[];
  
  /** IDs de comandos que originaram este evento */
  commandIds?: string[];
}

/**
 * Timestamp preciso com informação de timezone
 */
export interface EventTimestamp {
  /** Timestamp em milliseconds (epoch) */
  epoch: number;
  
  /** ISO 8601 string com timezone */
  iso: string;
  
  /** Offset do timezone em minutos */
  timezoneOffset: number;
  
  /** Se o timestamp foi sincronizado via NTP */
  ntpSynced?: boolean;
}

/**
 * Informação de origem do evento
 */
export interface EventOrigin {
  /** Tipo de origem: 'agent' | 'system' | 'external' */
  type: 'agent' | 'system' | 'external';
  
  /** Identificador da origem */
  id: string;
  
  /** Hostname/máquina onde o evento foi gerado */
  host?: string;
  
  /** Região/cloud onde o evento foi gerado */
  region?: string;
  
  /** Versão do software que gerou o evento */
  softwareVersion?: string;
}

/**
 * Informação de segurança do evento
 */
export interface EventSecurity {
  /** Nível de classificação: 'public' | 'internal' | 'confidential' | 'restricted' */
  classification: 'public' | 'internal' | 'confidential' | 'restricted';
  
  /** Se o payload está encriptado */
  encrypted: boolean;
  
  /** Algoritmo de encriptação usado (se aplicável) */
  encryptionAlgorithm?: string;
  
  /** Hash do payload (SHA-256) */
  payloadHash: string;
  
  /** Assinatura digital do evento */
  signature?: string;
  
  /** Algoritmo de assinatura */
  signatureAlgorithm?: string;
  
  /** Thumbprint da chave que assinou */
  signerThumbprint?: string;
}

/**
 * Informação de schema e validação
 */
export interface EventSchema {
  /** Nome do schema/tipo do evento */
  type: string;
  
  /** Versão do schema (para evolução) */
  version: string;
  
  /** Content-Type do payload (JSON, Avro, Protobuf, etc.) */
  contentType: string;
  
  /** Se o payload foi validado contra o schema */
  validated: boolean;
  
  /** Erros de validação (se houver) */
  validationErrors?: string[];
}

// ============================================================================
// EventEnvelope - Tipo Principal
// ============================================================================

/**
 * Envelope universal para eventos com rastreabilidade completa
 * 
 * @template T - Tipo do payload (definido pelo usuário)
 */
export interface EventEnvelope<T = unknown> {
  // --------------------------------------------------------------------------
  // Identificação Única
  // --------------------------------------------------------------------------
  
  /** ID único deste evento (UUID v7 ou ULID) */
  eventId: EventId;
  
  /** Tipo/nome do evento (ex: 'user.created', 'payment.processed') */
  eventType: string;
  
  /** Versão do tipo do evento (para evolução de schema) */
  eventVersion: EventVersion;
  
  // --------------------------------------------------------------------------
  // Agregação e Correlação
  // --------------------------------------------------------------------------
  
  /** ID do aggregate (DDD) ao qual este evento pertence */
  aggregateId: AggregateId;
  
  /** Tipo do aggregate */
  aggregateType: string;
  
  /** ID de correlação (para agrupar eventos relacionados) */
  correlationId: CorrelationId;
  
  /** ID do evento que causou este evento (causalidade) */
  causationId?: CausationId;
  
  // --------------------------------------------------------------------------
  // Timestamping
  // --------------------------------------------------------------------------
  
  /** Quando o evento ocorreu */
  timestamp: EventTimestamp;
  
  /** Quando o evento foi persistido (pode ser diferente do timestamp) */
  persistedAt?: EventTimestamp;
  
  // --------------------------------------------------------------------------
  // Contexto
  // --------------------------------------------------------------------------
  
  /** Contexto de execução */
  context: EventContext;
  
  /** Origem do evento */
  origin: EventOrigin;
  
  // --------------------------------------------------------------------------
  // Dados
  // --------------------------------------------------------------------------
  
  /** Payload do evento (dados de negócio - schema livre) */
  payload: T;
  
  /** Metadata adicional (extensível) */
  metadata?: Record<string, unknown>;
  
  // --------------------------------------------------------------------------
  // Segurança
  // --------------------------------------------------------------------------
  
  /** Informação de segurança */
  security: EventSecurity;
  
  // --------------------------------------------------------------------------
  // Schema
  // --------------------------------------------------------------------------
  
  /** Informação do schema */
  schema: EventSchema;
  
  // --------------------------------------------------------------------------
  // Evidence Chain (opcional, para eventos que requerem validade legal)
  // --------------------------------------------------------------------------
  
  /** Hash do evento anterior (para cadeia imutável) */
  previousHash?: string;
  
  /** Prova de inclusão em Merkle Tree */
  merkleProof?: string;
  
  /** Assinaturas de testemunhas */
  witnessSignatures?: string[];
  
  /** Cadeia de custódia */
  custodyChain?: string[];
}

// ============================================================================
// Builder Pattern para Criar EventEnvelope
// ============================================================================

/**
 * Opções para criar um EventEnvelope
 */
export interface EventEnvelopeOptions<T> {
  eventType: string;
  aggregateId: string;
  aggregateType: string;
  correlationId?: string;
  causationId?: string;
  payload: T;
  agentId: string;
  conversationId?: string;
  tenantId?: string;
  classification?: EventSecurity['classification'];
  encrypted?: boolean;
  contentType?: string;
  metadata?: Record<string, unknown>;
  enableEvidence?: boolean;
}

/**
 * Builder para criar EventEnvelopes com todos os campos necessários
 */
export class EventEnvelopeBuilder<T = unknown> {
  private eventId!: EventId;
  private eventType!: string;
  private eventVersion!: EventVersion;
  private aggregateId!: AggregateId;
  private aggregateType!: string;
  private correlationId!: CorrelationId;
  private causationId?: CausationId;
  private timestamp!: EventTimestamp;
  private context!: EventContext;
  private origin!: EventOrigin;
  private payload!: T;
  private metadata?: Record<string, unknown>;
  private security!: EventSecurity;
  private schema!: EventSchema;
  private previousHash?: string;
  private enableEvidence = false;

  /**
   * Inicializa o builder com valores padrão
   */
  constructor() {
    this.reset();
  }

  /**
   * Reseta o builder para estado inicial
   */
  reset(): this {
    this.eventId = EventIdStamp.of(generateEventId());
    this.eventVersion = EventVersionStamp.of(1);
    this.timestamp = createTimestamp();
    this.correlationId = CorrelationIdStamp.of(generateCorrelationId());
    this.enableEvidence = false;
    this.previousHash = undefined;
    this.metadata = undefined;
    return this;
  }

  /**
   * Define o tipo do evento
   */
  setEventType(eventType: string): this {
    this.eventType = eventType;
    return this;
  }

  /**
   * Define o aggregate
   */
  setAggregate(aggregateId: string, aggregateType: string): this {
    this.aggregateId = AggregateIdStamp.of(aggregateId);
    this.aggregateType = aggregateType;
    return this;
  }

  /**
   * Define IDs de correlação e causalidade
   */
  setCorrelation(correlationId?: string, causationId?: string): this {
    if (correlationId) {
      this.correlationId = CorrelationIdStamp.of(correlationId);
    }
    if (causationId) {
      this.causationId = CausationIdStamp.of(causationId);
    }
    return this;
  }

  /**
   * Define o payload
   */
  setPayload(payload: T): this {
    this.payload = payload;
    return this;
  }

  /**
   * Define o contexto de execução
   */
  setContext(
    agentId: AgentId | string,
    conversationId?: ConversationId | string,
    tenantId?: string,
    traceId?: TraceId | string,
    spanId?: string | SpanId
  ): this {
    this.context = {
      agentId: (typeof agentId === 'string' ? AgentIdStamp.of(agentId) : agentId) as AgentId,
      conversationId: (conversationId ? (typeof conversationId === 'string' ? ConversationIdStamp.of(conversationId) : conversationId) : undefined) as ConversationId | undefined,
      tenantId,
      traceId: (traceId ? (typeof traceId === 'string' ? TraceIdStamp.of(traceId) : traceId) : generateTraceId()) as TraceId,
      spanId: (spanId ? (typeof spanId === 'string' ? SpanIdStamp.of(spanId) : spanId) : generateSpanId()) as SpanId,
    };
    return this;
  }

  /**
   * Define a origem do evento
   */
  setOrigin(
    type: EventOrigin['type'],
    id: string,
    host?: string,
    region?: string,
    softwareVersion?: string
  ): this {
    this.origin = {
      type,
      id,
      host,
      region,
      softwareVersion,
    };
    return this;
  }

  /**
   * Define metadata adicional
   */
  setMetadata(metadata: Record<string, unknown>): this {
    this.metadata = metadata;
    return this;
  }

  /**
   * Define informação de segurança
   */
  setSecurity(
    classification: EventSecurity['classification'] = 'internal',
    encrypted = false,
    encryptionAlgorithm?: string
  ): this {
    const payloadHash = computePayloadHash(this.payload);
    
    this.security = {
      classification,
      encrypted,
      encryptionAlgorithm,
      payloadHash,
    };
    return this;
  }

  /**
   * Define informação do schema
   */
  setSchema(
    type: string,
    version: string,
    contentType: string = 'application/json',
    validated = false,
    validationErrors?: string[]
  ): this {
    this.schema = {
      type,
      version,
      contentType,
      validated,
      validationErrors,
    };
    return this;
  }

  /**
   * Define hash do evento anterior (para evidence chain)
   */
  setPreviousHash(hash: string): this {
    this.previousHash = hash;
    return this;
  }

  /**
   * Habilita evidence chain (adiciona campos opcionais)
   */
  enableEvidenceChain(): this {
    this.enableEvidence = true;
    return this;
  }

  /**
   * Constrói o EventEnvelope
   */
  build(): EventEnvelope<T> {
    const envelope: EventEnvelope<T> = {
      eventId: this.eventId,
      eventType: this.eventType,
      eventVersion: this.eventVersion,
      aggregateId: this.aggregateId,
      aggregateType: this.aggregateType,
      correlationId: this.correlationId,
      causationId: this.causationId ?? undefined,
      timestamp: this.timestamp,
      context: this.context,
      origin: this.origin,
      payload: this.payload,
      metadata: this.metadata ?? undefined,
      security: this.security,
      schema: this.schema,
    };

    if (this.previousHash) {
      envelope.previousHash = this.previousHash;
    }

    if (this.enableEvidence) {
      envelope.merkleProof = ''; // Será preenchido pelo EventStore
      envelope.witnessSignatures = [];
      envelope.custodyChain = [];
    }

    return envelope;
  }
}

/**
 * Cria um novo EventEnvelope com opções
 */
export function createEventEnvelope<T>(
  options: EventEnvelopeOptions<T>
): EventEnvelope<T> {
  return new EventEnvelopeBuilder<T>()
    .setEventType(options.eventType)
    .setAggregate(options.aggregateId, options.aggregateType)
    .setCorrelation(options.correlationId)
    .setContext(
      options.agentId as AgentId,
      options.conversationId as ConversationId,
      options.tenantId
    )
    .setOrigin('agent', options.agentId as AgentId)
    .setPayload(options.payload)
    .setMetadata(options.metadata || {})
    .setSecurity(
      options.classification ?? 'internal',
      options.encrypted ?? false
    )
    .setSchema(options.eventType, '1.0.0', options.contentType ?? 'application/json')
    .build();
}

// ============================================================================
// Funções Utilitárias
// ============================================================================

/**
 * Gera um ID único para evento (UUID v7 ou ULID)
 */
function generateEventId(): string {
  return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Gera um ID de correlação
 */
function generateCorrelationId(): string {
  return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Gera um Trace ID (W3C Trace Context - 32 hex chars)
 */
function generateTraceId(): TraceId {
  const bytes = crypto.randomBytes(16);
  return TraceIdStamp.of(bytes.toString('hex'));
}

/**
 * Gera um Span ID (W3C Trace Context - 16 hex chars)
 */
function generateSpanId(): SpanId {
  const bytes = crypto.randomBytes(8);
  return SpanIdStamp.of(bytes.toString('hex'));
}

/**
 * Cria um timestamp com informação completa
 */
function createTimestamp(): EventTimestamp {
  const now = new Date();
  return {
    epoch: now.getTime(),
    iso: now.toISOString(),
    timezoneOffset: now.getTimezoneOffset(),
    ntpSynced: false,
  };
}

/**
 * Computa hash SHA-256 do payload
 */
function computePayloadHash(payload: unknown): string {
  const p = payload as any;
  const serialized = JSON.stringify(p, p && typeof p === 'object' ? Object.keys(p).sort() : undefined);
  const hash = crypto.createHash('sha256').update(serialized).digest('hex');
  return `sha256:${hash}`;
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard para verificar se um objeto é um EventEnvelope
 */
export function isEventEnvelope(obj: unknown): obj is EventEnvelope {
  if (typeof obj !== 'object' || obj === null) return false;
  
  const env = obj as Record<string, unknown>;
  
  return (
    typeof env['eventId'] === 'string' &&
    typeof env['eventType'] === 'string' &&
    typeof env['aggregateId'] === 'string' &&
    typeof env['correlationId'] === 'string' &&
    typeof env['timestamp'] === 'object' &&
    typeof env['context'] === 'object' &&
    'payload' in env &&
    typeof env['security'] === 'object'
  );
}

/**
 * Extrai o payload tipado de um EventEnvelope
 */
export function getEnvelopePayload<T>(envelope: EventEnvelope<T>): T {
  return envelope.payload;
}

/**
 * Extrai metadata de rastreabilidade de um EventEnvelope
 */
export function getEnvelopeTracking(envelope: EventEnvelope): {
  eventId: string;
  eventType: string;
  aggregateId: string;
  correlationId: string;
  causationId?: string;
  traceId: string;
  spanId: string;
  timestamp: number;
} {
  return {
    eventId: envelope.eventId,
    eventType: envelope.eventType,
    aggregateId: envelope.aggregateId,
    correlationId: envelope.correlationId,
    causationId: envelope.causationId,
    traceId: envelope.context.traceId,
    spanId: envelope.context.spanId,
    timestamp: envelope.timestamp.epoch,
  };
}

// Import para funções crypto
import * as crypto from 'node:crypto';
