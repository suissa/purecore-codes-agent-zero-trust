import { Brand, STAMP } from "../../../src/semantic/shim";
import { MessagePart } from "./task";

/**
 * Message - Comunicação entre cliente e agente remoto A2A
 */
export type Message = Brand<{
  /** ID único da mensagem */
  id: string;
  /** Papel da mensagem (user ou agent) */
  role: 'user' | 'agent';
  /** Partes que compõem a mensagem */
  parts: MessagePart[];
  /** Timestamp da mensagem */
  timestamp: number;
  /** ID do contexto (opcional) */
  contextId?: string;
  /** Metadados adicionais */
  metadata?: Record<string, unknown>;
}, "a2a.core.message">;

/**
 * SendMessageRequest - Requisição para envio de mensagem
 */
export type SendMessageRequest = Brand<{
  /** Mensagem a ser enviada */
  message: Message;
  /** ID da task (opcional, para continuar conversa existente) */
  taskId?: string;
  /** Configurações de processamento */
  config?: MessageConfig;
}, "a2a.core.sendMessageRequest">;

export type MessageConfig = {
  /** Timeout em milissegundos */
  timeout?: number;
  /** Prioridade da mensagem */
  priority?: 'low' | 'normal' | 'high';
  /** Configurações de streaming */
  streaming?: StreamingConfig;
};

export type StreamingConfig = {
  /** Habilitar streaming */
  enabled: boolean;
  /** Intervalo entre updates em ms */
  updateInterval?: number;
};

export const Message = (() => {
  const f = STAMP<"a2a.core.message">();
  
  return {
    of: (v: unknown): Message => {
      if (!v || typeof v !== 'object') {
        throw new TypeError("Message deve ser um objeto");
      }
      
      const message = v as any;
      
      if (!message.id || typeof message.id !== 'string') {
        throw new TypeError("Message.id é obrigatório e deve ser string");
      }
      
      if (!message.role || !['user', 'agent'].includes(message.role)) {
        throw new TypeError("Message.role deve ser 'user' ou 'agent'");
      }
      
      if (!Array.isArray(message.parts)) {
        throw new TypeError("Message.parts deve ser um array");
      }
      
      if (!message.timestamp || typeof message.timestamp !== 'number') {
        throw new TypeError("Message.timestamp é obrigatório e deve ser number");
      }
      
      return f.of(message);
    },
    
    un: (v: Message) => f.un(v),
    
    make: (data: {
      id: string;
      role: 'user' | 'agent';
      parts: MessagePart[];
      contextId?: string;
      timestamp?: number;
      metadata?: Record<string, unknown>;
    }): Message => f.of({
      timestamp: Date.now(),
      ...data
    }),
    
    /** Cria uma mensagem de texto simples */
    text: (role: 'user' | 'agent', content: string, options?: {
      id?: string;
      contextId?: string;
      metadata?: Record<string, unknown>;
    }): Message => {
      return f.of({
        id: options?.id || generateMessageId(),
        role,
        parts: [{ type: 'text', content }],
        timestamp: Date.now(),
        contextId: options?.contextId,
        metadata: options?.metadata
      });
    },
    
    /** Extrai todo o texto das partes da mensagem */
    extractText: (message: Message): string => {
      const data = f.un(message);
      return data.parts
        .filter(part => part.type === 'text')
        .map(part => (part as any).content)
        .join('\n');
    }
  };
})();

export const SendMessageRequest = (() => {
  const f = STAMP<"a2a.core.sendMessageRequest">();
  
  return {
    of: (v: unknown): SendMessageRequest => {
      if (!v || typeof v !== 'object') {
        throw new TypeError("SendMessageRequest deve ser um objeto");
      }
      
      const request = v as any;
      
      if (!request.message) {
        throw new TypeError("SendMessageRequest.message é obrigatório");
      }
      
      return f.of(request);
    },
    
    un: (v: SendMessageRequest) => f.un(v),
    
    make: (data: {
      message: Message;
      taskId?: string;
      config?: MessageConfig;
    }): SendMessageRequest => f.of(data)
  };
})();

function generateMessageId(): string {
  return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}