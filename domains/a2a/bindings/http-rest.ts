/**
 * HTTP/REST Binding para protocolo A2A
 * Implementa mapeamento das operações A2A para endpoints REST
 */

import { A2AOperations, StreamEvent, ListTasksResponse } from "../protocol/operations";
import { Task } from "../core/task";
import { Message, SendMessageRequest } from "../core/message";
import { AgentCard } from "../core/agent-card";

/**
 * Mapeamento de operações A2A para endpoints HTTP/REST
 */
export const A2A_REST_ENDPOINTS = {
  // Core operations
  SEND_MESSAGE: 'POST /a2a/v1/messages',
  SEND_STREAMING_MESSAGE: 'POST /a2a/v1/messages/stream',
  GET_TASK: 'GET /a2a/v1/tasks/{taskId}',
  LIST_TASKS: 'GET /a2a/v1/tasks',
  CANCEL_TASK: 'POST /a2a/v1/tasks/{taskId}/cancel',
  SUBSCRIBE_TO_TASK: 'GET /a2a/v1/tasks/{taskId}/stream',
  GET_AGENT_CARD: 'GET /a2a/v1/agent',
  
  // Push notification operations
  SET_PUSH_NOTIFICATION_CONFIG: 'PUT /a2a/v1/tasks/{taskId}/push-config/{configId}',
  GET_PUSH_NOTIFICATION_CONFIG: 'GET /a2a/v1/tasks/{taskId}/push-config/{configId}',
  DELETE_PUSH_NOTIFICATION_CONFIG: 'DELETE /a2a/v1/tasks/{taskId}/push-config/{configId}'
} as const;

/**
 * Códigos de status HTTP específicos do A2A
 */
export const A2A_HTTP_STATUS = {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  
  // Client errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  NOT_ACCEPTABLE: 406,
  CONFLICT: 409,
  UNSUPPORTED_MEDIA_TYPE: 415,
  UNPROCESSABLE_ENTITY: 422,
  
  // Server errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  SERVICE_UNAVAILABLE: 503
} as const;

/**
 * Estrutura de erro HTTP A2A
 */
export interface A2AHttpError {
  error: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
  path: string;
}

/**
 * Adapter que converte operações A2A para HTTP/REST
 */
export class A2AHttpRestAdapter {
  constructor(private operations: A2AOperations) {}

  /**
   * Processa requisição HTTP e retorna resposta
   */
  async handleRequest(
    method: string,
    path: string,
    query: Record<string, any>,
    body: any,
    headers: Record<string, string>
  ): Promise<{ status: number; body: any; headers?: Record<string, string> }> {
    try {
      const route = `${method} ${path}`;
      
      // Rotear para método apropriado
      const result = await this.routeRequest(route, path, query, body, headers);
      
      return {
        status: A2A_HTTP_STATUS.OK,
        body: result
      };

    } catch (error) {
      return this.createErrorResponse(error, path);
    }
  }

  /**
   * Roteamento de requisições HTTP para operações A2A
   */
  private async routeRequest(
    route: string,
    path: string,
    query: Record<string, any>,
    body: any,
    headers: Record<string, string>
  ): Promise<any> {
    
    // POST /a2a/v1/messages
    if (route.startsWith('POST /a2a/v1/messages') && !route.includes('/stream')) {
      return await this.operations.sendMessage(body);
    }
    
    // POST /a2a/v1/messages/stream
    if (route === 'POST /a2a/v1/messages/stream') {
      // Para streaming, retornar generator não é adequado para HTTP
      // Implementação real usaria Server-Sent Events ou WebSockets
      throw new Error('Streaming not supported in HTTP/REST binding');
    }
    
    // GET /a2a/v1/tasks/{taskId}
    if (route.startsWith('GET /a2a/v1/tasks/') && !path.includes('/stream')) {
      const taskId = this.extractTaskId(path);
      const options = {
        historyLength: query.historyLength ? parseInt(query.historyLength) : undefined,
        includeArtifacts: query.includeArtifacts === 'true'
      };
      return await this.operations.getTask(taskId, options);
    }
    
    // GET /a2a/v1/tasks
    if (route === 'GET /a2a/v1/tasks') {
      const options = {
        contextId: query.contextId,
        status: query.status,
        pageSize: query.pageSize ? parseInt(query.pageSize) : undefined,
        pageToken: query.pageToken,
        historyLength: query.historyLength ? parseInt(query.historyLength) : undefined,
        lastUpdatedAfter: query.lastUpdatedAfter ? parseInt(query.lastUpdatedAfter) : undefined,
        includeArtifacts: query.includeArtifacts === 'true'
      };
      return await this.operations.listTasks(options);
    }
    
    // POST /a2a/v1/tasks/{taskId}/cancel
    if (route.startsWith('POST /a2a/v1/tasks/') && path.includes('/cancel')) {
      const taskId = this.extractTaskId(path);
      return await this.operations.cancelTask(taskId);
    }
    
    // GET /a2a/v1/tasks/{taskId}/stream
    if (route.startsWith('GET /a2a/v1/tasks/') && path.includes('/stream')) {
      // Para streaming, retornar generator não é adequado para HTTP
      throw new Error('Task streaming not supported in HTTP/REST binding');
    }
    
    // GET /a2a/v1/agent
    if (route === 'GET /a2a/v1/agent') {
      return await this.operations.getAgentCard();
    }
    
    throw new Error(`Route not found: ${route}`);
  }

  /**
   * Extrai taskId do path
   */
  private extractTaskId(path: string): string {
    const match = path.match(/\/tasks\/([^\/]+)/);
    if (!match) {
      throw new Error('Invalid task path');
    }
    return match[1];
  }

  /**
   * Mapeia erros A2A para códigos HTTP
   */
  private mapErrorToHttpStatus(error: any): number {
    if (error.code) {
      switch (error.code) {
        case 'CONTENT_TYPE_NOT_SUPPORTED':
          return A2A_HTTP_STATUS.UNSUPPORTED_MEDIA_TYPE;
        case 'UNSUPPORTED_OPERATION':
          return A2A_HTTP_STATUS.NOT_IMPLEMENTED;
        case 'TASK_NOT_FOUND':
          return A2A_HTTP_STATUS.NOT_FOUND;
        case 'TASK_NOT_CANCELABLE':
          return A2A_HTTP_STATUS.CONFLICT;
        case 'PUSH_NOTIFICATION_NOT_SUPPORTED':
          return A2A_HTTP_STATUS.NOT_IMPLEMENTED;
      }
    }
    
    return A2A_HTTP_STATUS.INTERNAL_SERVER_ERROR;
  }

  /**
   * Cria resposta de erro HTTP
   */
  private createErrorResponse(error: any, path: string): { status: number; body: A2AHttpError } {
    const status = this.mapErrorToHttpStatus(error);
    
    return {
      status,
      body: {
        error: {
          code: error.code || 'INTERNAL_ERROR',
          message: error.message || 'Internal server error',
          details: error.details
        },
        timestamp: new Date().toISOString(),
        path
      }
    };
  }
}

/**
 * Cliente HTTP/REST para comunicação A2A
 */
export class A2AHttpRestClient {
  constructor(private baseUrl: string) {}

  /**
   * Envia mensagem via HTTP/REST
   */
  async sendMessage(request: SendMessageRequest): Promise<Task | Message> {
    const response = await this.request('POST', '/a2a/v1/messages', request);
    return response;
  }

  /**
   * Obtém task via HTTP/REST
   */
  async getTask(taskId: string, options?: any): Promise<Task> {
    const queryParams = new URLSearchParams();
    if (options?.historyLength) queryParams.set('historyLength', options.historyLength.toString());
    if (options?.includeArtifacts) queryParams.set('includeArtifacts', options.includeArtifacts.toString());
    
    const query = queryParams.toString();
    const url = `/a2a/v1/tasks/${taskId}${query ? '?' + query : ''}`;
    
    return await this.request('GET', url);
  }

  /**
   * Lista tasks via HTTP/REST
   */
  async listTasks(options?: any): Promise<ListTasksResponse> {
    const queryParams = new URLSearchParams();
    if (options?.contextId) queryParams.set('contextId', options.contextId);
    if (options?.status) queryParams.set('status', options.status);
    if (options?.pageSize) queryParams.set('pageSize', options.pageSize.toString());
    if (options?.pageToken) queryParams.set('pageToken', options.pageToken);
    if (options?.historyLength) queryParams.set('historyLength', options.historyLength.toString());
    if (options?.lastUpdatedAfter) queryParams.set('lastUpdatedAfter', options.lastUpdatedAfter.toString());
    if (options?.includeArtifacts) queryParams.set('includeArtifacts', options.includeArtifacts.toString());
    
    const query = queryParams.toString();
    const url = `/a2a/v1/tasks${query ? '?' + query : ''}`;
    
    return await this.request('GET', url);
  }

  /**
   * Cancela task via HTTP/REST
   */
  async cancelTask(taskId: string): Promise<Task> {
    return await this.request('POST', `/a2a/v1/tasks/${taskId}/cancel`);
  }

  /**
   * Obtém Agent Card via HTTP/REST
   */
  async getAgentCard(): Promise<AgentCard> {
    return await this.request('GET', '/a2a/v1/agent');
  }

  /**
   * Executa requisição HTTP
   */
  private async request(method: string, path: string, body?: any): Promise<any> {
    const url = `${this.baseUrl}${path}`;
    
    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const error = new Error(errorBody.error?.message || `HTTP ${response.status}`);
      (error as any).code = errorBody.error?.code;
      (error as any).details = errorBody.error?.details;
      throw error;
    }

    return await response.json();
  }
}

/**
 * Servidor HTTP/REST para expor operações A2A
 */
export class A2AHttpRestServer {
  private adapter: A2AHttpRestAdapter;

  constructor(operations: A2AOperations) {
    this.adapter = new A2AHttpRestAdapter(operations);
  }

  /**
   * Middleware Express para HTTP/REST
   */
  expressMiddleware() {
    return async (req: any, res: any) => {
      try {
        const result = await this.adapter.handleRequest(
          req.method,
          req.path,
          req.query,
          req.body,
          req.headers
        );

        res.status(result.status);
        
        if (result.headers) {
          Object.entries(result.headers).forEach(([key, value]) => {
            res.setHeader(key, value);
          });
        }

        res.json(result.body);
      } catch (error) {
        res.status(500).json({
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error'
          },
          timestamp: new Date().toISOString(),
          path: req.path
        });
      }
    };
  }
}