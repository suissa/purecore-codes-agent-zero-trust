/**
 * EventSourcing Proxy - Proxy automático para encapsulamento de eventos
 * 
 * Este proxy intercepta as chamadas de métodos do agente e automaticamente:
 * 1. Captura o retorno (payload) do método
 * 2. Cria um EventEnvelope com toda a metadata de rastreabilidade
 * 3. Persiste o evento no EventStore
 * 4. Emite o evento para observers
 * 5. Retorna apenas o payload para o chamador (transparente)
 * 
 * @module EventSourcingProxy
 */

import { EventEmitter } from 'node:events';
import {
  type EventEnvelope,
  createEventEnvelope,
  getEnvelopeTracking,
} from './EventEnvelope';
import { type AgentId, type ConversationId } from '../types/index';

// ============================================================================
// Configuração do Proxy
// ============================================================================

/**
 * Configuração para o EventSourcingProxy
 */
export interface EventSourcingProxyConfig {
  /** ID do agente */
  agentId: AgentId;
  
  /** ID da conversa/sessão */
  conversationId?: ConversationId;
  
  /** ID do tenant */
  tenantId?: string;
  
  /** Tipo do aggregate (DDD) */
  aggregateType: string;
  
  /** Classificação de segurança padrão */
  defaultClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
  
  /** Se deve encriptar payloads por padrão */
  encryptByDefault?: boolean;
  
  /** Se deve habilitar evidence chain */
  enableEvidence?: boolean;
  
  /** Hostname/região para origem dos eventos */
  origin?: {
    host?: string;
    region?: string;
    softwareVersion?: string;
  };
  
  /** Se deve emitir eventos para um EventEmitter */
  eventEmitter?: EventEmitter;
  
  /** Se deve persistir eventos em um store */
  eventStore?: EventStore;
  
  /** Se deve logar eventos (para debug) */
  logEvents?: boolean;
}

/**
 * Interface para EventStore (persistência de eventos)
 */
export interface EventStore {
  /** Persiste um evento */
  append<T>(envelope: EventEnvelope<T>): Promise<void>;
  
  /** Recupera eventos de um aggregate */
  getEvents(aggregateId: string): Promise<EventEnvelope[]>;
  
  /** Recupera o último hash para evidence chain */
  getLastHash(aggregateId: string): Promise<string | undefined>;
}

/**
 * Interface para métodos que devem ser "event-sourced"
 */
export type EventSourcedMethod<TArgs extends unknown[] = unknown[], TReturn = unknown> = (
  ...args: TArgs
) => TReturn | Promise<TReturn>;

// ============================================================================
// EventSourcingProxy Class
// ============================================================================

/**
 * Proxy que automaticamente encapsula retornos de métodos em EventEnvelopes
 * 
 * @template T - Tipo do objeto sendo "proxyfied" (geralmente um Agente)
 */
export class EventSourcingProxy<T extends Record<string, any>> {
  private config: EventSourcingProxyConfig;
  private eventEmitter?: EventEmitter;
  private eventStore?: EventStore;
  private logEvents: boolean;
  private lastHashes: Map<string, string> = new Map();

  constructor(config: EventSourcingProxyConfig) {
    this.config = {
      defaultClassification: 'internal',
      encryptByDefault: false,
      enableEvidence: false,
      logEvents: false,
      ...config,
    };

    this.eventEmitter = config.eventEmitter;
    this.eventStore = config.eventStore;
    this.logEvents = config.logEvents ?? false;
  }

  /**
   * Cria um proxy para um objeto, interceptando métodos específicos
   * 
   * @param target - Objeto alvo (ex: SignalE2EEAgent)
   * @param methods - Lista de nomes de métodos para interceptar
   * @returns O objeto original envolto em proxy
   * 
   * @example
   * ```typescript
   * const agent = new SignalE2EEAgent('agent-1', authority);
   * 
   * const proxy = EventSourcingProxy.create(agent, {
   *   agentId: 'agent-1',
   *   aggregateType: 'Agent',
   *   eventStore: myEventStore,
   * });
   * 
   * // Agora, quando chamar agent.sendMessage(), o retorno será
   * // automaticamente encapsulado em um EventEnvelope
   * const result = await proxy.sendMessage('peer', 'hello');
   * // ← result é o payload puro, mas o evento foi persistido
   * ```
   */
  create(
    target: T,
    methods: (keyof T)[]
  ): T {
    const self = this;

    // Cria o proxy
    const proxy = new Proxy(target, {
      get(target, prop: string | symbol, receiver) {
        const originalMethod = (target as any)[prop];

        // Se não for função, retorna o valor original
        if (typeof originalMethod !== 'function') {
          return Reflect.get(target, prop, receiver);
        }

        // Se o método não estiver na lista de métodos para interceptar,
        // retorna o método original
        if (!methods.includes(prop as keyof T)) {
          return Reflect.get(target, prop, receiver);
        }

        // Retorna um método "wrapper" que intercepta a chamada
        return async function (...args: unknown[]) {
          // Chama o método original
          const result = await Reflect.apply(originalMethod, target, args);

          // Se o resultado for null/undefined, não cria evento
          if (result === null || result === undefined) {
            return result;
          }

          // Cria o EventEnvelope com o resultado (payload)
          const envelope = await self.createEnvelope(
            String(prop),
            result,
            args
          );

          // Persiste o evento (se eventStore configurado)
          if (self.eventStore) {
            await self.eventStore.append(envelope);
            
            // Atualiza o último hash para evidence chain
            if (envelope.security.payloadHash) {
              self.lastHashes.set(
                envelope.aggregateId,
                envelope.security.payloadHash
              );
            }
          }

          // Emite o evento (se eventEmitter configurado)
          if (self.eventEmitter) {
            self.eventEmitter.emit('event', envelope);
            self.eventEmitter.emit(`event:${envelope.eventType}`, envelope);
          }

          // Log (se habilitado)
          if (self.logEvents) {
            const tracking = getEnvelopeTracking(envelope);
            console.log(`📦 [EventSourced] ${envelope.eventType}`, {
              eventId: tracking.eventId,
              aggregateId: tracking.aggregateId,
              correlationId: tracking.correlationId,
              timestamp: new Date(tracking.timestamp).toISOString(),
            });
          }

          // Retorna APENAS o payload (transparente para o chamador)
          return result;
        };
      },
    });

    return proxy;
  }

  /**
   * Cria um EventEnvelope para um método chamado
   */
  private async createEnvelope(
    methodName: string,
    payload: unknown,
    args: unknown[]
  ): Promise<EventEnvelope> {
    // Obtém o último hash para evidence chain
    const aggregateId = `${this.config.aggregateType}-${this.config.agentId}`;
    const lastHash = this.eventStore
      ? await this.eventStore.getLastHash(aggregateId)
      : this.lastHashes.get(aggregateId);

    // Cria o envelope
    const envelope = createEventEnvelope({
      eventType: `${this.config.aggregateType.toLowerCase()}.${methodName}`,
      aggregateId,
      aggregateType: this.config.aggregateType,
      agentId: this.config.agentId,
      conversationId: this.config.conversationId,
      tenantId: this.config.tenantId,
      payload,
      classification: this.config.defaultClassification,
      encrypted: this.config.encryptByDefault,
      enableEvidence: this.config.enableEvidence,
      metadata: {
        methodName,
        argsCount: args.length,
        argsSummary: this.summarizeArgs(args),
      },
    });

    // Adiciona previousHash se existir (evidence chain)
    if (lastHash) {
      (envelope as any).previousHash = lastHash;
    }

    // Adiciona informação de origem
    if (this.config.origin) {
      (envelope as any).origin = {
        ...(envelope as any).origin,
        ...this.config.origin,
      };
    }

    return envelope;
  }

  /**
   * Cria um resumo dos argumentos (para logging/metadata)
   */
  private summarizeArgs(args: unknown[]): Record<string, unknown> {
    return args.map((arg) => {
      if (typeof arg === 'string') {
        return arg.length > 50 ? arg.substring(0, 50) + '...' : arg;
      }
      if (typeof arg === 'number' || typeof arg === 'boolean') {
        return arg;
      }
      if (typeof arg === 'object' && arg !== null) {
        // Resumo de objetos
        const keys = Object.keys(arg);
        return `{${keys.length} keys}`;
      }
      return typeof arg;
    }).reduce((acc, val, idx) => {
      acc[`arg${idx}`] = val;
      return acc;
    }, {} as Record<string, unknown>);
  }

  /**
   * Acessa o eventStore (para testes/inspeção)
   */
  getEventStore(): EventStore | undefined {
    return this.eventStore;
  }

  /**
   * Acessa o eventEmitter (para testes/inspeção)
   */
  getEventEmitter(): EventEmitter | undefined {
    return this.eventEmitter;
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Cria um EventSourcingProxy para um objeto
 * 
 * @param target - Objeto alvo
 * @param config - Configuração do proxy
 * @param methods - Métodos para interceptar
 * @returns Objeto proxyfied
 * 
 * @example
 * ```typescript
 * const agent = new SignalE2EEAgent('agent-1', authority);
 * 
 * const eventSourcedAgent = createEventSourcingProxy(
 *   agent,
 *   {
 *     agentId: 'agent-1',
 *     aggregateType: 'Agent',
 *     eventStore: myEventStore,
 *     logEvents: true,
 *   },
 *   ['sendMessage', 'receiveMessage', 'establishSession']
 * );
 * 
 * // Uso transparente
 * const encrypted = await eventSourcedAgent.sendMessage('peer', 'hello');
 * // ← Automaticamente persistido como evento
 * ```
 */
export function createEventSourcingProxy<T extends Record<string, any>>(
  target: T,
  config: EventSourcingProxyConfig,
  methods: (keyof T)[]
): T {
  const proxy = new EventSourcingProxy<T>(config);
  return proxy.create(target, methods);
}

// ============================================================================
// In-Memory EventStore (para exemplos/desenvolvimento)
// ============================================================================

/**
 * EventStore em memória (para desenvolvimento/testes)
 */
export class InMemoryEventStore implements EventStore {
  private events: EventEnvelope[] = [];
  private byAggregate: Map<string, EventEnvelope[]> = new Map();
  private lastHashes: Map<string, string> = new Map();

  async append<T>(envelope: EventEnvelope<T>): Promise<void> {
    this.events.push(envelope);

    // Indexa por aggregate
    const aggregateId = envelope.aggregateId;
    if (!this.byAggregate.has(aggregateId)) {
      this.byAggregate.set(aggregateId, []);
    }
    this.byAggregate.get(aggregateId)!.push(envelope);

    // Atualiza último hash
    this.lastHashes.set(aggregateId, envelope.security.payloadHash);
  }

  async getEvents(aggregateId: string): Promise<EventEnvelope[]> {
    return this.byAggregate.get(aggregateId) ?? [];
  }

  async getLastHash(aggregateId: string): Promise<string | undefined> {
    return this.lastHashes.get(aggregateId);
  }

  /**
   * Limpa todos os eventos (para testes)
   */
  clear(): void {
    this.events = [];
    this.byAggregate.clear();
    this.lastHashes.clear();
  }

  /**
   * Retorna todos os eventos (para inspeção)
   */
  getAllEvents(): EventEnvelope[] {
    return [...this.events];
  }
}

// ============================================================================
// Exemplo de Uso
// ============================================================================

/**
 * Exemplo de uso do EventSourcingProxy
 * 
 * @example
 * ```typescript
 * import { SignalE2EEAgent, TokenAuthority } from './index';
 * import { createEventSourcingProxy, InMemoryEventStore } from './EventSourcingProxy';
 * 
 * // 1. Criar agente
 * const authority = new TokenAuthority();
 * const agent = new SignalE2EEAgent('agent-1', authority);
 * await agent.initialize();
 * 
 * // 2. Criar EventStore
 * const eventStore = new InMemoryEventStore();
 * 
 * // 3. Criar proxy com EventSourcing automático
 * const eventSourcedAgent = createEventSourcingProxy(
 *   agent,
 *   {
 *     agentId: 'agent-1',
 *     aggregateType: 'SecureAgent',
 *     eventStore,
 *     logEvents: true,
 *     defaultClassification: 'confidential',
 *   },
 *   ['sendMessage', 'receiveMessage', 'establishSession']
 * );
 * 
 * // 4. Usar o agente (transparente)
 * const encryptedMessage = await eventSourcedAgent.sendMessage('peer', 'hello');
 * 
 * // ← Automaticamente:
 * // - Método sendMessage foi chamado
 * // - Retorno (encryptedMessage) capturado
 * // - EventEnvelope criado com metadata completa
 * // - Evento persistido no eventStore
 * // - Evento emitido para observers
 * // - encryptedMessage retornado para o chamador
 * 
 * // 5. Inspecionar eventos
 * const events = await eventStore.getEvents('SecureAgent-agent-1');
 * console.log(events); // [EventEnvelope { eventType: 'secureagent.sendMessage', ... }]
 * ```
 */
