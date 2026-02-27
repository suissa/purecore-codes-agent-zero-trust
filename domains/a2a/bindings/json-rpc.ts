/**
 * JSON-RPC 2.0 Binding para protocolo A2A
 * Implementa mapeamento das operações A2A para métodos JSON-RPC
 */

import { A2AOperations, StreamEvent, ListTasksResponse } from "../protocol/operations";
import { Task } from "../core/task";
import { Message, SendMessageRequest } from "../core/message";
import { AgentCard } from "../core/agent-card";

/**
 * Mapeamento de operações A2A para métodos JSON-RPC 2.0
 */
export const A2A_JSONRPC_METHODS = {
  // Core operations
  SEND_MESSAGE: 'a2a.message.send',
  SEND_STREAMING_MESSAGE: 'a2a.message.sendStreaming',
  GET_TASK: 'a2a.tasks.get',
  LIST_TASKS: 'a2a.tasks.list',
  CANCEL_TASK: 'a2a.tasks.cancel',
  SUBSCRIBE_TO_TASK: 'a2a.tasks.subscribe',
  GET_AGENT_CARD: 'a2a.agent.getCard',
  
  // Push notification operations
  SET_PUSH_NOTIFICATION_CONFIG: 'a2a.tasks.pushNotificationConfig.set',
  GET_PUSH_NOTIFICATION_CONFIG: 'a2a.tasks.pushNotificationConfig.get',
  DELETE_PUSH_NOTIFICATION_CONFIG: 'a2a.tasks.pushNotificationConfig.delete'
} as const;

/**
 * Estruturas de requisição/resposta JSON-RPC
 */
export interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params?: any;
  id: string | number | null;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  result?: any;
  error?: JsonRpcError;
  id: string | number | null;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: any;
}

/**
 * Códigos de erro JSON-RPC específicos do A2A
 */
export const A2A_ERROR_CODES = {
  // Erros padrão JSON-RPC
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  
  // Erros específicos A2A (range -32000 to -32099)
  CONTENT_TYPE_NOT_SUPPORTED: -32001,
  UNSUPPORTED_OPERATION: -32002,
  TASK_NOT_FOUND: -32003,
  TASK_NOT_CANCELABLE: -32004,
  PUSH_NOTIFICATION_NOT_SUPPORTED: -32005,
  AGENT_NOT_FOUND: -32006,
  AUTHENTICATION_FAILED: -32007,
  AUTHORIZATION_FAILED: -32008
} as const;

/**
 * Adapter que converte operações A2A para JSON-RPC
 */
export class A2AJsonRpcAdapter {
  constructor(private operations: A2AOperations) {}

  /**
   * Processa uma requisição JSON-RPC e retorna a resposta
   */
  async handleRequest(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    try {
      // Validar estrutura básica JSON-RPC
      if (request.jsonrpc !== '2.0') {
        return this.createErrorResponse(
          request.id,
          A2A_ERROR_CODES.INVALID_REQUEST,
          'Invalid JSON-RPC version'
        );
      }

      if (!request.method) {
        return this.createErrorResponse(
          request.id,
          A2A_ERROR_CODES.INVALID_REQUEST,
          'Missing method'
        );
      }

      // Rotear para método apropriado
      const result = await this.routeMethod(request.method, request.params);
      
      return {
        jsonrpc: '2.0',
        result,
        id: request.id
      };

    } catch (error) {
      return this.createErrorResponse(
        request.id,
        this.mapErrorToCode(error),
        error.message,
        error
      );
    }
  }

  /**
   * Roteamento de métodos JSON-RPC para operações A2A
   */
  private async routeMethod(method: string, params: any): Promise<any> {
    switch (method) {
      case A2A_JSONRPC_METHODS.SEND_MESSAGE:
        return await this.operations.sendMessage(params);

      case A2A_JSONRPC_METHODS.GET_TASK:
        return await this.operations.getTask(params.taskId, params.options);

      case A2A_JSONRPC_METHODS.LIST_TASKS:
        return await this.operations.listTasks(params);

      case A2A_JSONRPC_METHODS.CANCEL_TASK:
        return await this.operations.cancelTask(params.taskId);

      case A2A_JSONRPC_METHODS.GET_AGENT_CARD:
        return await this.operations.getAgentCard();

      default:
        throw new Error(`Method not found: ${method}`);
    }
  }

  /**
   * Mapeia erros A2A para códigos JSON-RPC
   */
  private mapErrorToCode(error: any): number {
    if (error.code) {
      switch (error.code) {
        case 'CONTENT_TYPE_NOT_SUPPORTED':
          return A2A_ERROR_CODES.CONTENT_TYPE_NOT_SUPPORTED;
        case 'UNSUPPORTED_OPERATION':
          return A2A_ERROR_CODES.UNSUPPORTED_OPERATION;
        case 'TASK_NOT_FOUND':
          return A2A_ERROR_CODES.TASK_NOT_FOUND;
        case 'TASK_NOT_CANCELABLE':
          return A2A_ERROR_CODES.TASK_NOT_CANCELABLE;
        case 'PUSH_NOTIFICATION_NOT_SUPPORTED':
          return A2A_ERROR_CODES.PUSH_NOTIFICATION_NOT_SUPPORTED;
      }
    }
    
    return A2A_ERROR_CODES.INTERNAL_ERROR;
  }

  /**
   * Cria resposta de erro JSON-RPC
   */
  private createErrorResponse(
    id: string | number | null,
    code: number,
    message: string,
    data?: any
  ): JsonRpcResponse {
    return {
      jsonrpc: '2.0',
      error: {
        code,
        message,
        data
      },
      id
    };
  }
}

/**
 * Cliente JSON-RPC para comunicação A2A
 */
export class A2AJsonRpcClient {
  private requestId = 0;

  constructor(private endpoint: string) {}

  /**
   * Envia mensagem via JSON-RPC
   */
  async sendMessage(request: SendMessageRequest): Promise<Task | Message> {
    return await this.call(A2A_JSONRPC_METHODS.SEND_MESSAGE, request);
  }

  /**
   * Obtém task via JSON-RPC
   */
  async getTask(taskId: string, options?: any): Promise<Task> {
    return await this.call(A2A_JSONRPC_METHODS.GET_TASK, { taskId, options });
  }

  /**
   * Lista tasks via JSON-RPC
   */
  async listTasks(options?: any): Promise<ListTasksResponse> {
    return await this.call(A2A_JSONRPC_METHODS.LIST_TASKS, options);
  }

  /**
   * Cancela task via JSON-RPC
   */
  async cancelTask(taskId: string): Promise<Task> {
    return await this.call(A2A_JSONRPC_METHODS.CANCEL_TASK, { taskId });
  }

  /**
   * Obtém Agent Card via JSON-RPC
   */
  async getAgentCard(): Promise<AgentCard> {
    return await this.call(A2A_JSONRPC_METHODS.GET_AGENT_CARD);
  }

  /**
   * Executa chamada JSON-RPC
   */
  private async call(method: string, params?: any): Promise<any> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      params,
      id: ++this.requestId
    };

    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const jsonResponse: JsonRpcResponse = await response.json();

    if (jsonResponse.error) {
      const error = new Error(jsonResponse.error.message);
      (error as any).code = jsonResponse.error.code;
      (error as any).data = jsonResponse.error.data;
      throw error;
    }

    return jsonResponse.result;
  }
}

/**
 * Servidor JSON-RPC para expor operações A2A
 */
export class A2AJsonRpcServer {
  private adapter: A2AJsonRpcAdapter;

  constructor(operations: A2AOperations) {
    this.adapter = new A2AJsonRpcAdapter(operations);
  }

  /**
   * Processa requisição HTTP JSON-RPC
   */
  async handleHttpRequest(body: string): Promise<string> {
    try {
      const request: JsonRpcRequest = JSON.parse(body);
      const response = await this.adapter.handleRequest(request);
      return JSON.stringify(response);
    } catch (error) {
      const errorResponse: JsonRpcResponse = {
        jsonrpc: '2.0',
        error: {
          code: A2A_ERROR_CODES.PARSE_ERROR,
          message: 'Parse error'
        },
        id: null
      };
      return JSON.stringify(errorResponse);
    }
  }

  /**
   * Middleware Express para JSON-RPC
   */
  expressMiddleware() {
    return async (req: any, res: any) => {
      if (req.method !== 'POST') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
      }

      const response = await this.handleHttpRequest(JSON.stringify(req.body));
      res.setHeader('Content-Type', 'application/json');
      res.send(response);
    };
  }
}