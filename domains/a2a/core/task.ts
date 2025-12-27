import { Brand, STAMP } from "../../../src/semantic/shim";

/**
 * Task - Unidade fundamental de trabalho gerenciada pelo protocolo A2A
 */
export type Task = Brand<{
  /** ID único da task */
  id: string;
  /** Status atual da task */
  status: TaskStatus;
  /** ID do contexto (opcional) para agrupar tasks relacionadas */
  contextId?: string;
  /** Timestamp de criação (ms desde epoch) */
  createdAt: number;
  /** Timestamp da última atualização (ms desde epoch) */
  updatedAt: number;
  /** Histórico de mensagens da task */
  messages: TaskMessage[];
  /** Artefatos gerados pela task */
  artifacts: TaskArtifact[];
  /** Metadados adicionais */
  metadata?: Record<string, unknown>;
}, "a2a.core.task">;

export type TaskStatus = 
  | 'pending'     // Task criada, aguardando processamento
  | 'running'     // Task em execução
  | 'completed'   // Task concluída com sucesso
  | 'failed'      // Task falhou
  | 'cancelled'   // Task cancelada
  | 'rejected';   // Task rejeitada

export type TaskMessage = {
  /** ID único da mensagem */
  id: string;
  /** Papel da mensagem (user ou agent) */
  role: 'user' | 'agent';
  /** Partes que compõem a mensagem */
  parts: MessagePart[];
  /** Timestamp da mensagem */
  timestamp: number;
};

export type MessagePart = 
  | TextPart
  | FilePart
  | DataPart;

export type TextPart = {
  type: 'text';
  content: string;
};

export type FilePart = {
  type: 'file';
  filename: string;
  mimeType: string;
  size: number;
  url?: string;
  data?: string; // Base64 encoded
};

export type DataPart = {
  type: 'data';
  schema: string;
  data: Record<string, unknown>;
};

export type TaskArtifact = {
  /** ID único do artefato */
  id: string;
  /** Nome do artefato */
  name: string;
  /** Tipo MIME do artefato */
  mimeType: string;
  /** Tamanho em bytes */
  size: number;
  /** Partes que compõem o artefato */
  parts: MessagePart[];
  /** Timestamp de criação */
  createdAt: number;
};

export const Task = (() => {
  const f = STAMP<"a2a.core.task">();
  
  return {
    of: (v: unknown): Task => {
      if (!v || typeof v !== 'object') {
        throw new TypeError("Task deve ser um objeto");
      }
      
      const task = v as any;
      
      if (!task.id || typeof task.id !== 'string') {
        throw new TypeError("Task.id é obrigatório e deve ser string");
      }
      
      if (!task.status || !isValidTaskStatus(task.status)) {
        throw new TypeError("Task.status é obrigatório e deve ser um status válido");
      }
      
      if (!task.createdAt || typeof task.createdAt !== 'number') {
        throw new TypeError("Task.createdAt é obrigatório e deve ser number");
      }
      
      if (!task.updatedAt || typeof task.updatedAt !== 'number') {
        throw new TypeError("Task.updatedAt é obrigatório e deve ser number");
      }
      
      return f.of(task);
    },
    
    un: (v: Task) => f.un(v),
    
    make: (data: {
      id: string;
      status: TaskStatus;
      contextId?: string;
      createdAt?: number;
      updatedAt?: number;
      messages?: TaskMessage[];
      artifacts?: TaskArtifact[];
      metadata?: Record<string, unknown>;
    }): Task => {
      const now = Date.now();
      return f.of({
        messages: [],
        artifacts: [],
        createdAt: now,
        updatedAt: now,
        ...data
      });
    },
    
    /** Verifica se a task está em estado terminal */
    isTerminal: (task: Task): boolean => {
      const data = f.un(task);
      return ['completed', 'failed', 'cancelled', 'rejected'].includes(data.status);
    },
    
    /** Verifica se a task pode ser cancelada */
    isCancelable: (task: Task): boolean => {
      const data = f.un(task);
      return ['pending', 'running'].includes(data.status);
    },
    
    /** Atualiza o status da task */
    updateStatus: (task: Task, status: TaskStatus): Task => {
      const data = f.un(task);
      return f.of({
        ...data,
        status,
        updatedAt: Date.now()
      });
    },
    
    /** Adiciona uma mensagem à task */
    addMessage: (task: Task, message: TaskMessage): Task => {
      const data = f.un(task);
      return f.of({
        ...data,
        messages: [...data.messages, message],
        updatedAt: Date.now()
      });
    },
    
    /** Adiciona um artefato à task */
    addArtifact: (task: Task, artifact: TaskArtifact): Task => {
      const data = f.un(task);
      return f.of({
        ...data,
        artifacts: [...data.artifacts, artifact],
        updatedAt: Date.now()
      });
    }
  };
})();

function isValidTaskStatus(status: string): status is TaskStatus {
  return ['pending', 'running', 'completed', 'failed', 'cancelled', 'rejected'].includes(status);
}