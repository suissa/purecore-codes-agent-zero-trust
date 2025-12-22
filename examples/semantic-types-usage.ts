/**
 * Exemplo prático de uso dos tipos semânticos para comunicação HTTP em MCP servers
 * 
 * Este exemplo demonstra como os tipos semânticos melhoram a segurança e legibilidade
 * do código relacionado à comunicação HTTP entre servidores MCP.
 */

import { ServerUrl } from '../domains/http/server/url';
import { HttpStatusCode, HTTP_STATUS } from '../domains/http/status/code';
import { HttpMethod, HTTP_METHOD } from '../domains/http/method/verb';
import { HttpContentType, CONTENT_TYPE } from '../domains/http/header/content-type';
import { BearerToken } from '../domains/auth/token/bearer';
import { McpServerEndpoint } from '../domains/mcp/server/endpoint';

// ============================================================================
// CONFIGURAÇÃO DE SERVIDORES MCP
// ============================================================================

interface McpServerConfig {
  id: string;
  endpoint: McpServerEndpoint;
  isInternal: boolean;
  requiresAuth: boolean;
}

const MCP_SERVERS: McpServerConfig[] = [
  {
    id: 'alpha',
    endpoint: McpServerEndpoint.make('https://mcp-alpha.internal/api/v1'),
    isInternal: true,
    requiresAuth: true
  },
  {
    id: 'beta', 
    endpoint: McpServerEndpoint.make('https://mcp-beta.internal/api/v1'),
    isInternal: true,
    requiresAuth: true
  },
  {
    id: 'external-service',
    endpoint: McpServerEndpoint.make('https://api.external-service.com/mcp'),
    isInternal: false,
    requiresAuth: true
  }
];

// ============================================================================
// CLIENTE HTTP TIPADO PARA MCP
// ============================================================================

interface HttpRequest {
  method: HttpMethod;
  url: McpServerEndpoint;
  headers: Record<string, string>;
  body?: string;
  contentType?: HttpContentType;
}

interface HttpResponse {
  status: HttpStatusCode;
  headers: Record<string, string>;
  body: string;
  contentType?: HttpContentType;
}

class TypedMcpClient {
  private authToken: BearerToken | null = null;

  constructor(token?: string) {
    if (token) {
      this.authToken = BearerToken.of(token);
    }
  }

  /**
   * Configura token de autenticação
   */
  setAuthToken(token: string): void {
    this.authToken = BearerToken.of(token);
    
    // Verificar se é JWT e se está expirado
    if (BearerToken.isJWT(this.authToken)) {
      if (BearerToken.isJWTExpired(this.authToken)) {
        console.warn('⚠️ Token JWT está expirado!');
      } else {
        const payload = BearerToken.getJWTPayload(this.authToken);
        console.log(`✅ Token JWT válido para usuário: ${payload.sub}`);
      }
    }
  }

  /**
   * Faz requisição HTTP tipada para servidor MCP
   */
  async request(config: {
    server: McpServerConfig;
    method: HttpMethod;
    path?: string;
    body?: any;
    contentType?: HttpContentType;
  }): Promise<HttpResponse> {
    
    // Construir URL completa
    const url = config.path 
      ? McpServerEndpoint.withPath(config.server.endpoint, config.path)
      : config.server.endpoint;

    // Verificar se servidor interno requer HTTPS
    if (config.server.isInternal && !McpServerEndpoint.isSecure(url)) {
      throw new Error(`Servidor interno ${config.server.id} deve usar HTTPS`);
    }

    // Preparar headers
    const headers: Record<string, string> = {};

    // Adicionar autenticação se necessária
    if (config.server.requiresAuth) {
      if (!this.authToken) {
        throw new Error(`Servidor ${config.server.id} requer autenticação`);
      }
      headers['Authorization'] = BearerToken.toAuthHeader(this.authToken);
    }

    // Adicionar Content-Type se há body
    if (config.body && HttpMethod.allowsBody(config.method)) {
      const contentType = config.contentType || CONTENT_TYPE.JSON;
      headers['Content-Type'] = HttpContentType.un(contentType);
    }

    // Simular requisição HTTP (em produção, usar fetch ou axios)
    console.log(`📤 ${HttpMethod.un(config.method)} ${McpServerEndpoint.un(url)}`);
    console.log(`   Headers:`, headers);
    if (config.body) {
      console.log(`   Body:`, config.body);
    }

    // Simular resposta
    const mockResponse: HttpResponse = {
      status: HTTP_STATUS.OK,
      headers: {
        'Content-Type': HttpContentType.un(CONTENT_TYPE.JSON),
        'Server': 'MCP-Server/1.0'
      },
      body: JSON.stringify({ 
        success: true, 
        server: config.server.id,
        timestamp: new Date().toISOString()
      }),
      contentType: CONTENT_TYPE.JSON
    };

    console.log(`📥 ${HttpStatusCode.un(mockResponse.status)} ${this.getStatusMessage(mockResponse.status)}`);
    
    return mockResponse;
  }

  /**
   * Métodos de conveniência para operações comuns
   */
  async get(server: McpServerConfig, path?: string): Promise<HttpResponse> {
    return this.request({
      server,
      method: HTTP_METHOD.GET,
      path
    });
  }

  async post(server: McpServerConfig, path: string, data: any): Promise<HttpResponse> {
    return this.request({
      server,
      method: HTTP_METHOD.POST,
      path,
      body: JSON.stringify(data),
      contentType: CONTENT_TYPE.JSON
    });
  }

  async put(server: McpServerConfig, path: string, data: any): Promise<HttpResponse> {
    return this.request({
      server,
      method: HTTP_METHOD.PUT,
      path,
      body: JSON.stringify(data),
      contentType: CONTENT_TYPE.JSON
    });
  }

  async delete(server: McpServerConfig, path: string): Promise<HttpResponse> {
    return this.request({
      server,
      method: HTTP_METHOD.DELETE,
      path
    });
  }

  /**
   * Utilitário para obter mensagem de status
   */
  private getStatusMessage(status: HttpStatusCode): string {
    const code = HttpStatusCode.un(status);
    
    if (HttpStatusCode.isSuccess(status)) {
      return '✅ Success';
    } else if (HttpStatusCode.isClientError(status)) {
      return '❌ Client Error';
    } else if (HttpStatusCode.isServerError(status)) {
      return '💥 Server Error';
    } else if (HttpStatusCode.isRedirection(status)) {
      return '🔄 Redirect';
    } else {
      return '📋 Info';
    }
  }
}

// ============================================================================
// EXEMPLO DE USO
// ============================================================================

async function demonstrateTypedMcpCommunication() {
  console.log('🚀 Demonstração de Comunicação HTTP Tipada para MCP Servers\n');

  // 1. Criar cliente com token JWT
  const jwtToken = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImFnZW50SWQiOiJhZ2VudC1hbHBoYSIsImNhcGFiaWxpdGllcyI6WyJyZWFzb25pbmciLCJtZW1vcnkiXSwiaWF0IjoxNzAzMjA4MDAwLCJleHAiOjE3MDMyMTE2MDAsImlzcyI6InVybjpzZWN1cmUtYWdlbnRzOmF1dGhvcml0eSIsImF1ZCI6InVybjpzZWN1cmUtYWdlbnRzOm5ldHdvcmsifQ.signature';
  
  const client = new TypedMcpClient();
  client.setAuthToken(jwtToken);

  console.log('');

  // 2. Listar servidores configurados
  console.log('📋 Servidores MCP configurados:');
  MCP_SERVERS.forEach(server => {
    const endpoint = server.endpoint;
    console.log(`   • ${server.id}: ${McpServerEndpoint.un(endpoint)}`);
    console.log(`     - Interno: ${McpServerEndpoint.isInternal(endpoint) ? '✅' : '❌'}`);
    console.log(`     - Seguro: ${McpServerEndpoint.isSecure(endpoint) ? '🔒' : '🔓'}`);
    console.log(`     - Auth: ${server.requiresAuth ? '🔑' : '🚫'}`);
  });

  console.log('\n' + '─'.repeat(60));
  console.log('💬 Executando operações tipadas...\n');

  // 3. Operações GET
  console.log('1️⃣ GET - Buscar status dos servidores:');
  for (const server of MCP_SERVERS) {
    await client.get(server, '/health');
  }

  console.log('\n2️⃣ POST - Enviar comando para servidor Alpha:');
  await client.post(MCP_SERVERS[0], '/commands', {
    action: 'process',
    data: { message: 'Hello from typed client!' }
  });

  console.log('\n3️⃣ PUT - Atualizar configuração do servidor Beta:');
  await client.put(MCP_SERVERS[1], '/config', {
    logLevel: 'debug',
    maxConnections: 100
  });

  console.log('\n4️⃣ DELETE - Limpar cache do servidor externo:');
  await client.delete(MCP_SERVERS[2], '/cache');

  // 4. Demonstrar validações de tipos
  console.log('\n' + '─'.repeat(60));
  console.log('🛡️ Demonstrando validações de tipos:\n');

  try {
    // Tentar criar URL inválida
    const invalidUrl = McpServerEndpoint.make('ftp://invalid-protocol.com');
  } catch (error) {
    console.log('❌ URL inválida rejeitada:', (error as Error).message);
  }

  try {
    // Tentar criar status code inválido
    const invalidStatus = HttpStatusCode.make(999);
  } catch (error) {
    console.log('❌ Status code inválido rejeitado:', (error as Error).message);
  }

  try {
    // Tentar criar método HTTP inválido
    const invalidMethod = HttpMethod.make('INVALID');
  } catch (error) {
    console.log('❌ Método HTTP inválido rejeitado:', (error as Error).message);
  }

  try {
    // Tentar criar token Bearer inválido
    const invalidToken = BearerToken.make('token with spaces');
  } catch (error) {
    console.log('❌ Token Bearer inválido rejeitado:', (error as Error).message);
  }

  // 5. Demonstrar utilitários dos tipos
  console.log('\n' + '─'.repeat(60));
  console.log('🔧 Demonstrando utilitários dos tipos:\n');

  const endpoint = MCP_SERVERS[0].endpoint;
  console.log(`🌐 Endpoint: ${McpServerEndpoint.un(endpoint)}`);
  console.log(`   • Base URL: ${McpServerEndpoint.getBaseUrl(endpoint)}`);
  console.log(`   • Path: ${McpServerEndpoint.getPath(endpoint)}`);
  console.log(`   • É interno: ${McpServerEndpoint.isInternal(endpoint)}`);
  console.log(`   • É seguro: ${McpServerEndpoint.isSecure(endpoint)}`);

  const contentType = CONTENT_TYPE.JSON_UTF8;
  console.log(`\n📄 Content-Type: ${HttpContentType.un(contentType)}`);
  console.log(`   • Tipo principal: ${HttpContentType.getMainType(contentType)}`);
  console.log(`   • Subtipo: ${HttpContentType.getSubType(contentType)}`);
  console.log(`   • Charset: ${HttpContentType.getCharset(contentType)}`);
  console.log(`   • É JSON: ${HttpContentType.isJson(contentType)}`);

  const method = HTTP_METHOD.POST;
  console.log(`\n🔧 Método: ${HttpMethod.un(method)}`);
  console.log(`   • É seguro: ${HttpMethod.isSafe(method)}`);
  console.log(`   • É idempotente: ${HttpMethod.isIdempotent(method)}`);
  console.log(`   • Permite body: ${HttpMethod.allowsBody(method)}`);

  console.log('\n✅ Demonstração concluída!');
  console.log('\n🎯 Benefícios dos tipos semânticos:');
  console.log('   • ✅ Validação automática de entrada');
  console.log('   • ✅ Prevenção de erros em tempo de compilação');
  console.log('   • ✅ Utilitários específicos do domínio');
  console.log('   • ✅ Código mais legível e autodocumentado');
  console.log('   • ✅ Refatoração mais segura');
}

// Executar demonstração
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateTypedMcpCommunication().catch(console.error);
}

export { TypedMcpClient, MCP_SERVERS };