import { Task } from "../core/task";
import { Message, SendMessageRequest } from "../core/message";
import { AgentCard } from "../core/agent-card";

/**
 * Operações core do protocolo A2A
 * Define as capacidades fundamentais que todos os agentes A2A devem suportar
 */

export interface A2AOperations {
  /** Enviar mensagem para um agente */
  sendMessage(request: SendMessageRequest): Promise<Task | Message>;
  
  /** Enviar mensagem com streaming de updates */
  sendStreamingMessage(request: SendMessageRequest): AsyncIterable<StreamEvent>;
  
  /** Obter estado atual de uma task */
  getTask(taskId: string, options?: GetTaskOptions): Promise<Task>;
  
  /** Listar tasks com filtros opcionais */
  listTasks(options?: ListTasksOptions): Promise<ListTasksResponse>;
  
  /** Cancelar uma task em andamento */
  cancelTask(taskId: string): Promise<Task>;
  
  /** Subscrever a updates de uma task */
  subscribeToTask(taskId: string): AsyncIterable<StreamEvent>;
  
  /** Obter Agent Card do agente */
  getAgentCard(): Promise<AgentCard>;
}

export type StreamEvent = 
  | TaskStatusUpdateEvent
  | TaskArtifactUpdateEvent
  | MessageEvent;

export type TaskStatusUpdateEvent = {
  type: 'task_status_update';
  taskId: string;
  status: string;
  timestamp: number;
};

export type TaskArtifactUpdateEvent = {
  type: 'task_artifact_update';
  taskId: string;
  artifactId: string;
  artifact: any;
  timestamp: number;
};

export type MessageEvent = {
  type: 'message';
  message: Message;
  timestamp: number;
};

export type GetTaskOptions = {
  /** Número máximo de mensagens no histórico */
  historyLength?: number;
  /** Incluir artefatos na resposta */
  includeArtifacts?: boolean;
};

export type ListTasksOptions = {
  /** Filtrar por ID de contexto */
  contextId?: string;
  /** Filtrar por status */
  status?: string;
  /** Tamanho da página */
  pageSize?: number;
  /** Token de paginação */
  pageToken?: string;
  /** Número máximo de mensagens no histórico de cada task */
  historyLength?: number;
  /** Filtrar tasks atualizadas após timestamp */
  lastUpdatedAfter?: number;
  /** Incluir artefatos nas tasks */
  includeArtifacts?: boolean;
};

export type ListTasksResponse = {
  /** Array de tasks */
  tasks: Task[];
  /** Token para próxima página */
  nextPageToken: string;
  /** Tamanho da página solicitada */
  pageSize: number;
  /** Número total de tasks disponíveis */
  totalSize: number;
};

/**
 * Erros específicos do protocolo A2A
 */
export class A2AError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'A2AError';
  }
}

export class ContentTypeNotSupportedError extends A2AError {
  constructor(contentType: string) {
    super(
      `Content type '${contentType}' is not supported`,
      'CONTENT_TYPE_NOT_SUPPORTED',
      { contentType }
    );
  }
}

export class UnsupportedOperationError extends A2AError {
  constructor(operation: string, reason?: string) {
    super(
      `Operation '${operation}' is not supported${reason ? ': ' + reason : ''}`,
      'UNSUPPORTED_OPERATION',
      { operation, reason }
    );
  }
}

export class TaskNotFoundError extends A2AError {
  constructor(taskId: string) {
    super(
      `Task '${taskId}' not found`,
      'TASK_NOT_FOUND',
      { taskId }
    );
  }
}

export class TaskNotCancelableError extends A2AError {
  constructor(taskId: string, status: string) {
    super(
      `Task '${taskId}' cannot be cancelled (current status: ${status})`,
      'TASK_NOT_CANCELABLE',
      { taskId, status }
    );
  }
}

export class PushNotificationNotSupportedError extends A2AError {
  constructor() {
    super(
      'Push notifications are not supported by this agent',
      'PUSH_NOTIFICATION_NOT_SUPPORTED'
    );
  }
}