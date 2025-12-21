import { SignJWT, jwtVerify, generateKeyPair } from './index'; // Importando nossa lib

// --- Cenário: Setup Inicial ---
// Em um cenário real, estas chaves seriam geradas uma vez e salvas em variáveis de ambiente ou KMS.
// O Auth Server tem a PRIVADA. As APIs têm a PÚBLICA.
const { privateKey: AUTH_SERVER_PRIVATE_KEY, publicKey: API_PUBLIC_KEY } = generateKeyPair();

// Identificadores do nosso sistema
const ISSUER = 'https://meu-auth-server.com'; // Quem gerou o token
const AUDIENCE_FINANCEIRO = 'https://api.financeira.com'; // API de Destino

// --- 1. O Authorization Server (Emissor) ---
// Função que gera um Access Token quando o usuário loga com sucesso
async function generateAccessToken(userId: string, scopes: string[]) {
  
  // No OAuth 2.1, o token geralmente tem validade curta (ex: 1 hora)
  const jwt = await new SignJWT({
    // Claims padrão do OAuth/OIDC
    sub: userId,           // Subject: Quem é o usuário (ID)
    scope: scopes.join(' '), // Scopes: O que ele pode fazer
    // Claims personalizadas
    role: 'admin' 
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE_FINANCEIRO) // DISS: "Este token é SÓ para o Financeiro"
    .setExpirationTime('1h') // Token de acesso de curta duração
    .setJti(crypto.randomUUID()) // ID único do token (para revogação/blacklist se necessário)
    .sign(AUTH_SERVER_PRIVATE_KEY);

  return jwt;
}

// --- 2. O Resource Server (API Financeira) ---
// Middleware que protege a rota da API
async function protectFinanceRoute(tokenRecebido: string) {
  try {
    const { payload } = await jwtVerify(tokenRecebido, API_PUBLIC_KEY, {
      issuer: ISSUER,               // Valida se veio do nosso Auth Server confiável
      audience: AUDIENCE_FINANCEIRO // Valida se o token foi feito PARA NÓS
    });

    // Se passou daqui, a assinatura é válida e a audiência está correta.
    console.log(`✅ Acesso permitido ao usuário ${payload.sub}`);
    console.log(`Escopos permitidos: ${payload.scope}`);
    
    return true;

  } catch (error) {
    console.error(`❌ Acesso negado: ${(error as Error).message}`);
    return false;
  }
}

// --- Simulação do Fluxo ---
(async () => {
  console.log("--- Iniciando Fluxo OAuth 2.1 com EdDSA ---\n");

  // 1. Usuário loga e ganha token
  console.log("1. Gerando Access Token no Auth Server...");
  const token = await generateAccessToken('user-123', ['read:invoices', 'write:payments']);
  console.log("Token gerado:\n", token);

  // 2. Usuário tenta acessar a API Financeira com o token
  console.log("\n2. Tentando acessar API Financeira...");
  await protectFinanceRoute(token);

  // 3. Teste de Audiência Inválida (Hacker tenta usar token em outra API)
  console.log("\n3. Teste de Segurança (Audiência Errada)...");
  // Vamos simular que a verificação espera 'api-de-chat' mas o token é para 'financeiro'
  try {
    await jwtVerify(token, API_PUBLIC_KEY, {
      issuer: ISSUER,
      audience: 'https://api.chat.com' // <--- Audiência diferente da que está no token
    });
  } catch (e) {
    console.log(`Bloqueio esperado: ${(e as Error).message}`);
  }

})();