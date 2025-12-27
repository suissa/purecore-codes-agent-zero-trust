/**
 * Exemplos práticos de validações rigorosas com falha rápida
 * Demonstra como os tipos semânticos detectam e rejeitam entradas inválidas
 */

import { ServerUrl } from '../domains/http/server/url';
import { HttpStatusCode, HTTP_STATUS } from '../domains/http/status/code';
import { HttpMethod, HTTP_METHOD } from '../domains/http/method/verb';
import { HttpContentType, CONTENT_TYPE } from '../domains/http/header/content-type';
import { BearerToken } from '../domains/auth/token/bearer';
import { McpServerEndpoint } from '../domains/mcp/server/endpoint';

console.log('🛡️ DEMONSTRAÇÃO DE VALIDAÇÕES RIGOROSAS\n');
console.log('Os tipos semânticos falham rapidamente com erros claros:\n');

// ============================================================================
// 1. VALIDAÇÕES DE URL DE SERVIDOR
// ============================================================================

console.log('1️⃣ ServerUrl - Validações de URLs de servidor:\n');

// ✅ URLs válidas
try {
  const validUrl1 = ServerUrl.make('https://api.example.com');
  const validUrl2 = ServerUrl.make('http://localhost:8080');
  const validUrl3 = ServerUrl.make('https://mcp-server.internal:9443/api');
  console.log('✅ URLs válidas aceitas');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Protocolo inválido
try {
  const invalidProtocol = ServerUrl.make('ftp://files.example.com');
  console.log('❌ FALHA: Protocolo inválido deveria ser rejeitado');
} catch (error) {
  console.log('✅ Protocolo inválido rejeitado:', (error as Error).message);
}

// ❌ URL malformada
try {
  const malformedUrl = ServerUrl.make('not-a-url-at-all');
  console.log('❌ FALHA: URL malformada deveria ser rejeitada');
} catch (error) {
  console.log('✅ URL malformada rejeitada:', (error as Error).message);
}

// ❌ Sem hostname
try {
  const noHostname = ServerUrl.make('https://');
  console.log('❌ FALHA: URL sem hostname deveria ser rejeitada');
} catch (error) {
  console.log('✅ URL sem hostname rejeitada:', (error as Error).message);
}

// ❌ String vazia
try {
  const emptyUrl = ServerUrl.make('');
  console.log('❌ FALHA: URL vazia deveria ser rejeitada');
} catch (error) {
  console.log('✅ URL vazia rejeitada:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 2. VALIDAÇÕES DE STATUS CODE HTTP
// ============================================================================

console.log('2️⃣ HttpStatusCode - Validações de códigos de status:\n');

// ✅ Status codes válidos
try {
  const validStatus1 = HttpStatusCode.make(200);
  const validStatus2 = HttpStatusCode.make(404);
  const validStatus3 = HttpStatusCode.make(500);
  console.log('✅ Status codes válidos aceitos');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Status code inexistente
try {
  const invalidStatus = HttpStatusCode.make(999);
  console.log('❌ FALHA: Status 999 deveria ser rejeitado');
} catch (error) {
  console.log('✅ Status code 999 rejeitado:', (error as Error).message);
}

// ❌ Status code negativo
try {
  const negativeStatus = HttpStatusCode.make(-1);
  console.log('❌ FALHA: Status negativo deveria ser rejeitado');
} catch (error) {
  console.log('✅ Status code negativo rejeitado:', (error as Error).message);
}

// ❌ Não é inteiro
try {
  const floatStatus = HttpStatusCode.make(200.5);
  console.log('❌ FALHA: Status decimal deveria ser rejeitado');
} catch (error) {
  console.log('✅ Status code decimal rejeitado:', (error as Error).message);
}

// ❌ String como número
try {
  const stringStatus = HttpStatusCode.make('200' as any);
  console.log('❌ FALHA: String "200" deveria ser rejeitada');
} catch (error) {
  console.log('✅ String como status rejeitada:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 3. VALIDAÇÕES DE MÉTODO HTTP
// ============================================================================

console.log('3️⃣ HttpMethod - Validações de métodos HTTP:\n');

// ✅ Métodos válidos
try {
  const validMethod1 = HttpMethod.make('GET');
  const validMethod2 = HttpMethod.make('post'); // Normalizado para uppercase
  const validMethod3 = HttpMethod.make('PATCH');
  console.log('✅ Métodos HTTP válidos aceitos (normalizados para uppercase)');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Método inexistente
try {
  const invalidMethod = HttpMethod.make('INVALID');
  console.log('❌ FALHA: Método INVALID deveria ser rejeitado');
} catch (error) {
  console.log('✅ Método INVALID rejeitado:', (error as Error).message);
}

// ❌ Método personalizado
try {
  const customMethod = HttpMethod.make('CUSTOM');
  console.log('❌ FALHA: Método CUSTOM deveria ser rejeitado');
} catch (error) {
  console.log('✅ Método CUSTOM rejeitado:', (error as Error).message);
}

// ❌ String vazia
try {
  const emptyMethod = HttpMethod.make('');
  console.log('❌ FALHA: Método vazio deveria ser rejeitado');
} catch (error) {
  console.log('✅ Método vazio rejeitado:', (error as Error).message);
}

// ❌ Espaços
try {
  const methodWithSpaces = HttpMethod.make('GET POST');
  console.log('❌ FALHA: Método com espaços deveria ser rejeitado');
} catch (error) {
  console.log('✅ Método com espaços rejeitado:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 4. VALIDAÇÕES DE CONTENT-TYPE
// ============================================================================

console.log('4️⃣ HttpContentType - Validações de Content-Type:\n');

// ✅ Content-Types válidos
try {
  const validContentType1 = HttpContentType.make('application/json');
  const validContentType2 = HttpContentType.make('text/html; charset=utf-8');
  const validContentType3 = HttpContentType.make('multipart/form-data; boundary=something');
  console.log('✅ Content-Types válidos aceitos');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Formato inválido (sem subtipo)
try {
  const noSubtype = HttpContentType.make('application');
  console.log('❌ FALHA: Content-Type sem subtipo deveria ser rejeitado');
} catch (error) {
  console.log('✅ Content-Type sem subtipo rejeitado:', (error as Error).message);
}

// ❌ Formato inválido (sem tipo principal)
try {
  const noMainType = HttpContentType.make('/json');
  console.log('❌ FALHA: Content-Type sem tipo principal deveria ser rejeitado');
} catch (error) {
  console.log('✅ Content-Type sem tipo principal rejeitado:', (error as Error).message);
}

// ❌ Caracteres inválidos
try {
  const invalidChars = HttpContentType.make('application/json<script>');
  console.log('❌ FALHA: Content-Type com caracteres inválidos deveria ser rejeitado');
} catch (error) {
  console.log('✅ Content-Type com caracteres inválidos rejeitado:', (error as Error).message);
}

// ❌ String vazia
try {
  const emptyContentType = HttpContentType.make('');
  console.log('❌ FALHA: Content-Type vazio deveria ser rejeitado');
} catch (error) {
  console.log('✅ Content-Type vazio rejeitado:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 5. VALIDAÇÕES DE BEARER TOKEN
// ============================================================================

console.log('5️⃣ BearerToken - Validações de tokens Bearer:\n');

// ✅ Tokens válidos
try {
  const validToken1 = BearerToken.make('eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature');
  const validToken2 = BearerToken.make('abcdef1234567890abcdef1234567890');
  const validToken3 = BearerToken.make('token-with-dashes_and_underscores.and.dots');
  console.log('✅ Bearer tokens válidos aceitos');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Token com espaços
try {
  const tokenWithSpaces = BearerToken.make('token with spaces');
  console.log('❌ FALHA: Token com espaços deveria ser rejeitado');
} catch (error) {
  console.log('✅ Token com espaços rejeitado:', (error as Error).message);
}

// ❌ Token muito curto (inseguro)
try {
  const shortToken = BearerToken.make('short');
  console.log('❌ FALHA: Token muito curto deveria ser rejeitado');
} catch (error) {
  console.log('✅ Token muito curto rejeitado:', (error as Error).message);
}

// ❌ Token vazio
try {
  const emptyToken = BearerToken.make('');
  console.log('❌ FALHA: Token vazio deveria ser rejeitado');
} catch (error) {
  console.log('✅ Token vazio rejeitado:', (error as Error).message);
}

// ❌ Caracteres inválidos
try {
  const invalidCharsToken = BearerToken.make('token@with#invalid$chars');
  console.log('❌ FALHA: Token com caracteres inválidos deveria ser rejeitado');
} catch (error) {
  console.log('✅ Token com caracteres inválidos rejeitado:', (error as Error).message);
}

// ❌ Header de autorização malformado
try {
  const malformedHeader = BearerToken.fromAuthHeader('Basic dXNlcjpwYXNz');
  console.log('❌ FALHA: Header Basic deveria ser rejeitado');
} catch (error) {
  console.log('✅ Header Basic rejeitado:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 6. VALIDAÇÕES DE ENDPOINT MCP
// ============================================================================

console.log('6️⃣ McpServerEndpoint - Validações de endpoints MCP:\n');

// ✅ Endpoints válidos
try {
  const validEndpoint1 = McpServerEndpoint.make('https://mcp-alpha.internal/api/v1');
  const validEndpoint2 = McpServerEndpoint.make('http://localhost:8080');
  const validEndpoint3 = McpServerEndpoint.make('https://api.external.com/mcp');
  console.log('✅ Endpoints MCP válidos aceitos');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ Protocolo inválido
try {
  const invalidProtocolEndpoint = McpServerEndpoint.make('ws://websocket.server.com');
  console.log('❌ FALHA: Protocolo WebSocket deveria ser rejeitado');
} catch (error) {
  console.log('✅ Protocolo WebSocket rejeitado:', (error as Error).message);
}

// ❌ Sem hostname
try {
  const noHostnameEndpoint = McpServerEndpoint.make('https:///api/v1');
  console.log('❌ FALHA: Endpoint sem hostname deveria ser rejeitado');
} catch (error) {
  console.log('✅ Endpoint sem hostname rejeitado:', (error as Error).message);
}

// ❌ URL completamente inválida
try {
  const invalidEndpoint = McpServerEndpoint.make('not-a-url');
  console.log('❌ FALHA: URL inválida deveria ser rejeitada');
} catch (error) {
  console.log('✅ URL inválida rejeitada:', (error as Error).message);
}

console.log('\n' + '─'.repeat(60) + '\n');

// ============================================================================
// 7. DEMONSTRAÇÃO DE VALIDAÇÕES EM CADEIA
// ============================================================================

console.log('7️⃣ Validações em cadeia - Falha no primeiro erro:\n');

interface HttpRequestConfig {
  url: McpServerEndpoint;
  method: HttpMethod;
  status: HttpStatusCode;
  contentType: HttpContentType;
  authToken: BearerToken;
}

function createHttpRequest(config: {
  url: string;
  method: string;
  status: number;
  contentType: string;
  authToken: string;
}): HttpRequestConfig {
  // As validações falham na primeira entrada inválida
  return {
    url: McpServerEndpoint.make(config.url),           // Valida primeiro
    method: HttpMethod.make(config.method),            // Depois este
    status: HttpStatusCode.make(config.status),        // Depois este
    contentType: HttpContentType.make(config.contentType), // Depois este
    authToken: BearerToken.make(config.authToken)      // Por último
  };
}

// ✅ Configuração válida
try {
  const validRequest = createHttpRequest({
    url: 'https://api.example.com/mcp',
    method: 'POST',
    status: 200,
    contentType: 'application/json',
    authToken: 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature'
  });
  console.log('✅ Configuração HTTP válida criada com sucesso');
} catch (error) {
  console.log('❌ Erro inesperado:', (error as Error).message);
}

// ❌ URL inválida (falha imediatamente, não checa os outros)
try {
  const invalidUrlRequest = createHttpRequest({
    url: 'ftp://invalid.com',      // ❌ Falha aqui
    method: 'INVALID_METHOD',      // Nem chega a validar este
    status: 999,                   // Nem chega a validar este
    contentType: 'invalid',        // Nem chega a validar este
    authToken: 'short'             // Nem chega a validar este
  });
  console.log('❌ FALHA: Deveria ter rejeitado URL inválida');
} catch (error) {
  console.log('✅ Falha rápida na URL inválida:', (error as Error).message);
}

// ❌ URL válida, mas método inválido
try {
  const invalidMethodRequest = createHttpRequest({
    url: 'https://api.example.com', // ✅ Passa
    method: 'INVALID_METHOD',       // ❌ Falha aqui
    status: 999,                    // Nem chega a validar
    contentType: 'invalid',         // Nem chega a validar
    authToken: 'short'              // Nem chega a validar
  });
  console.log('❌ FALHA: Deveria ter rejeitado método inválido');
} catch (error) {
  console.log('✅ Falha rápida no método inválido:', (error as Error).message);
}

console.log('\n' + '═'.repeat(60));
console.log('🎯 RESUMO DAS VALIDAÇÕES RIGOROSAS');
console.log('═'.repeat(60));
console.log('');
console.log('✅ CARACTERÍSTICAS:');
console.log('   • Falha rápida: Para na primeira validação que falha');
console.log('   • Erros claros: Mensagens específicas sobre o que está errado');
console.log('   • Validação completa: Verifica formato, faixa, caracteres permitidos');
console.log('   • Segurança: Rejeita entradas potencialmente perigosas');
console.log('   • Consistência: Mesmo padrão de validação em todos os tipos');
console.log('');
console.log('❌ TIPOS DE ERROS DETECTADOS:');
console.log('   • Formatos inválidos (URLs malformadas, Content-Types sem subtipo)');
console.log('   • Valores fora da faixa (status codes inexistentes, tokens muito curtos)');
console.log('   • Caracteres proibidos (espaços em tokens, caracteres especiais)');
console.log('   • Protocolos inseguros (FTP em URLs, WebSocket em endpoints MCP)');
console.log('   • Entradas vazias ou nulas');
console.log('');
console.log('🛡️ BENEFÍCIOS:');
console.log('   • Detecta problemas antes que causem falhas em produção');
console.log('   • Facilita debugging com mensagens de erro específicas');
console.log('   • Previne ataques de injeção e dados malformados');
console.log('   • Melhora a confiabilidade do sistema');
console.log('   • Reduz bugs relacionados a tipos de dados incorretos');
console.log('');