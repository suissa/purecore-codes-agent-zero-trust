import { TokenManager, TokenSet } from "../domains/auth/manager/token-manager";
import { generateDPoPKeyPair } from "../domains/auth/dpop";

// --- MOCK INFRASTRUCTURE ---

// Estado do "Servidor"
let serverAccessToken = "access_token_v1";
let refreshCallCount = 0;
let requestCallCount = 0;

// Simula uma API real que retorna 401 se o token não for o esperado (expirado)
const mockFetch = async (
  accessToken: string,
  dpopProof?: string,
): Promise<string> => {
  requestCallCount++;
  await new Promise((resolve) => setTimeout(resolve, 100)); // Latência de rede

  if (accessToken !== serverAccessToken) {
    console.log(`🔒 [Server] Recusando token antigo: ${accessToken}`);
    const err: any = new Error("Unauthorized");
    err.status = 401; // Simula erro HTTP
    throw err;
  }

  // Se passou, verifica se tem prova DPoP (se enviada)
  if (dpopProof) {
    if (!dpopProof.includes("eyJ"))
      throw new Error("Invalid DPoP Proof format");
  }

  return `Success data for token ${accessToken}`;
};

// Simula endpoint de refresh (lento)
const mockRefresh = async (refreshToken: string): Promise<TokenSet> => {
  console.log("⏳ [Server] Processando refresh token... (Simulando lentidão)");
  refreshCallCount++;

  await new Promise((resolve) => setTimeout(resolve, 500)); // 500ms de delay

  serverAccessToken = "access_token_v2"; // Rotaciona o token no servidor

  return {
    accessToken: serverAccessToken,
    refreshToken: "new_refresh_token",
    expiresAt: Date.now() + 3600000, // +1h
    tokenType: "DPoP",
  };
};

// --- DEMONSTRAÇÃO ---

async function main() {
  console.log("🚀 Iniciando Demo: Self-Healing DPoP Token Manager\n");

  // 1. Setup
  const dpopKeys = generateDPoPKeyPair("ES256");

  const manager = new TokenManager({
    initialToken: {
      accessToken: "access_token_v1_EXPIRADO", // Começamos com token já "errado" para forçar erro
      refreshToken: "initial_refresh_token",
      expiresAt: Date.now() - 10000,
      tokenType: "DPoP",
    },
    refreshTokenFunction: mockRefresh,
    dpopKeyPair: dpopKeys,
  });

  serverAccessToken = "access_token_v2"; // Servidor já está na v2, cliente na v1 (inválido)

  console.log(
    "📋 Cenário: Cliente tem token expirado. Lançaremos 5 requests SIMULTÂNEOS.",
  );
  console.log(
    "   Esperado: TODAS falhem com 401, APENAS UM refresh ocorra, e TODAS tentem novamente com sucesso.\n",
  );

  // 2. Lança 5 requisições em paralelo
  const requests = Array.from({ length: 5 }).map(async (_, i) => {
    const id = i + 1;
    console.log(`⚡ [Client] Disparando Request #${id}`);

    try {
      const result = await manager.authenticatedRequest(
        "GET",
        `https://api.com/resource/${id}`,
        async (token, proof) => {
          // Função que faz o fetch real (mockado aqui)
          return mockFetch(token, proof);
        },
      );
      console.log(`✅ [Client] Request #${id} finalizada: "${result}"`);
    } catch (e) {
      console.error(`❌ [Client] Request #${id} falhou drasticamente:`, e);
    }
  });

  await Promise.all(requests);

  // 3. Resultados
  console.log("\n📊 Estatísticas Finais:");
  console.log(
    `   Total de Requests Disparados (incluindo retries): ${requestCallCount}`,
  );
  console.log(`   Total de Refreshes realizados: ${refreshCallCount}`);

  if (refreshCallCount === 1) {
    console.log(
      "✅ SUCESSO! Ocorreu apenas 1 refresh para 5 falhas simultâneas (Promise Latching funcionou).",
    );
  } else {
    console.error(
      `❌ FALHA! Ocorreram ${refreshCallCount} refreshes. Deveria ser apenas 1.`,
    );
  }

  // Verifica se o token final no manager é o v2
  const currentToken = await manager.getValidToken();
  if (currentToken.accessToken === "access_token_v2") {
    console.log("✅ Token final sincronizado corretamente.");
  } else {
    console.error("❌ Token final incorreto.");
  }
}

main().catch(console.error);
