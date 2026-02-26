import * as crypto from 'node:crypto';
import { SignJWT, jwtVerify, generateKeyPair } from './index'; // Importando nossa lib

// --- Cenário: Setup Inicial ---
const { privateKey: AUTH_SERVER_PRIVATE_KEY, publicKey: API_PUBLIC_KEY } = generateKeyPair();

const ISSUER = 'https://meu-auth-server.com';

// Audiences do nosso sistema

const MCP_ECOSYSTEM_AUD = 'urn:mcp:ecosystem'; // Audiência que representa TODOS os seus MCPs

// URLs específicas de alguns servidores MCP
const MCP_SERVER_ALPHA = 'https://mcp-alpha.internal';
const MCP_SERVER_BETA  = 'https://mcp-beta.internal';
const MCP_SERVER_GAMA  = 'https://mcp-gama.internal';
const MCP_SERVER_DELTA = 'https://mcp-delta.internal'; // Este ficará de fora do grupo

// --- 1. O Authorization Server (Emissor) ---
// Agora aceita 'audience' dinâmico (pode ser string única ou array)
async function generateAccessToken(userId: string, scopes: string[], audience: string | string[]) {
  
  const jwt = await new SignJWT({
    sub: userId,
    scope: scopes.join(' '),
    role: 'user'
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(audience) // Aceita string ou array de strings
    .setExpirationTime('1h')
    .setJti(crypto.randomUUID())
    .sign(AUTH_SERVER_PRIVATE_KEY);

  return jwt;
}

// --- 2. O Resource Server (Simulação de um MCP Server) ---
// Cada servidor sabe QUEM ELE É (sua própria URL ou ID de audiência)
async function protectMCPServer(serverName: string, myAudienceId: string, tokenRecebido: string) {
  try {
    // Ao verificar, o servidor passa 'myAudienceId'.
    // A validação passa se 'myAudienceId' estiver presente na lista 'aud' do token.
    const { payload } = await jwtVerify(tokenRecebido, API_PUBLIC_KEY, {
      issuer: ISSUER,
      audience: myAudienceId 
    });

    console.log(`✅ [${serverName}] Acesso permitido! (Token aud: ${JSON.stringify(payload.aud)})`);
    return true;

  } catch (error) {
    console.error(`❌ [${serverName}] Acesso negado: ${(error as Error).message}`);
    return false;
  }
}

// --- Simulação dos Cenários ---
(async () => {
  console.log("--- Cenário A: Token para um Ecossistema Inteiro ---\n");
  // Útil se você tem muitos microserviços e todos confiam no mesmo token 'geral'
  
  const tokenEcosystem = await generateAccessToken('user-A', ['mcp:read'], MCP_ECOSYSTEM_AUD);
  
  // O servidor Alpha aceita tokens do ecossistema
  // Nota: O servidor precisa estar configurado para aceitar 'urn:mcp:ecosystem' como audiência válida
  await protectMCPServer('MCP Alpha (Modo Ecossistema)', MCP_ECOSYSTEM_AUD, tokenEcosystem);


  console.log("\n--- Cenário B: Token Restrito a um Grupo Específico (3 Servers) ---\n");
  // O usuário quer acessar Alpha, Beta e Gama, mas NÃO o Delta.
  
  const targetGroup = [MCP_SERVER_ALPHA, MCP_SERVER_BETA, MCP_SERVER_GAMA];
  const tokenGroup = await generateAccessToken('user-B', ['mcp:write'], targetGroup);
  
  // 1. MCP Alpha tenta validar (Ele espera ver sua URL no token)
  await protectMCPServer('MCP Alpha', MCP_SERVER_ALPHA, tokenGroup);

  // 2. MCP Gama tenta validar
  await protectMCPServer('MCP Gama', MCP_SERVER_GAMA, tokenGroup);

  // 3. MCP Delta tenta validar (Ele NÃO está na lista do token)
  await protectMCPServer('MCP Delta', MCP_SERVER_DELTA, tokenGroup);

})();