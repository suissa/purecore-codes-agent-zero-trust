import { Brand, STAMP } from "../../../src/semantic/shim";

/**
 * Agent Card - Documento de metadados que descreve identidade, capacidades e endpoint de um agente A2A
 */
export type AgentCard = Brand<{
  /** Identificador único do agente */
  agentId: string;
  /** Nome amigável do agente */
  name: string;
  /** Descrição das capacidades do agente */
  description: string;
  /** Versão do protocolo A2A suportada */
  protocolVersion: string;
  /** Endpoint base para comunicação A2A */
  endpoint: string;
  /** Capacidades suportadas pelo agente */
  capabilities: AgentCapabilities;
  /** Configurações de autenticação */
  authentication: AuthenticationConfig;
  /** Metadados adicionais */
  metadata?: Record<string, unknown>;
}, "a2a.core.agentCard">;

export type AgentCapabilities = {
  /** Suporte a streaming de mensagens */
  streaming: boolean;
  /** Suporte a push notifications */
  pushNotifications: boolean;
  /** Tipos de conteúdo suportados */
  supportedContentTypes: string[];
  /** Operações suportadas */
  supportedOperations: string[];
};

export type AuthenticationConfig = {
  /** Tipo de autenticação (jwt, mtls, oauth2) */
  type: 'jwt' | 'mtls' | 'oauth2';
  /** Configurações específicas do tipo */
  config: Record<string, unknown>;
};

export const AgentCard = (() => {
  const f = STAMP<"a2a.core.agentCard">();
  
  return {
    of: (v: unknown): AgentCard => {
      if (!v || typeof v !== 'object') {
        throw new TypeError("AgentCard deve ser um objeto");
      }
      
      const card = v as any;
      
      if (!card.agentId || typeof card.agentId !== 'string') {
        throw new TypeError("AgentCard.agentId é obrigatório e deve ser string");
      }
      
      if (!card.name || typeof card.name !== 'string') {
        throw new TypeError("AgentCard.name é obrigatório e deve ser string");
      }
      
      if (!card.endpoint || typeof card.endpoint !== 'string') {
        throw new TypeError("AgentCard.endpoint é obrigatório e deve ser string");
      }
      
      if (!card.protocolVersion || typeof card.protocolVersion !== 'string') {
        throw new TypeError("AgentCard.protocolVersion é obrigatório e deve ser string");
      }
      
      return f.of(card);
    },
    
    un: (v: AgentCard) => f.un(v),
    
    make: (data: {
      agentId: string;
      name: string;
      description: string;
      protocolVersion: string;
      endpoint: string;
      capabilities: AgentCapabilities;
      authentication: AuthenticationConfig;
      metadata?: Record<string, unknown>;
    }): AgentCard => f.of(data),
    
    /** Valida se o AgentCard suporta uma operação específica */
    supportsOperation: (card: AgentCard, operation: string): boolean => {
      const data = f.un(card);
      return data.capabilities.supportedOperations.includes(operation);
    },
    
    /** Valida se o AgentCard suporta um tipo de conteúdo específico */
    supportsContentType: (card: AgentCard, contentType: string): boolean => {
      const data = f.un(card);
      return data.capabilities.supportedContentTypes.includes(contentType);
    }
  };
})();