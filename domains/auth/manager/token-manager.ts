import { createDPoPProof, DPoPKeyPair, DPoPAlgorithm } from "../dpop";

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // Timestamp in ms
  tokenType: string;
}

export type RefreshTokenFunction = (refreshToken: string) => Promise<TokenSet>;

export interface TokenManagerConfig {
  initialToken?: TokenSet;
  refreshTokenFunction: RefreshTokenFunction;
  dpopKeyPair?: DPoPKeyPair;
  clockToleranceMs?: number;
}

/**
 * Gerenciador de Tokens com Self-Healing e Suporte a DPoP
 *
 * Implementa o padrão "Promise Latching" para evitar condições de corrida
 * durante o refresh de tokens (Self-Healing).
 */
export class TokenManager {
  private token: TokenSet | null;
  private refreshPromise: Promise<TokenSet> | null = null;
  private config: TokenManagerConfig;

  constructor(config: TokenManagerConfig) {
    this.config = {
      clockToleranceMs: 5000, // 5 segundos de tolerância
      ...config,
    };
    this.token = config.initialToken || null;
  }

  /**
   * Obtém um token válido, realizando refresh se necessário.
   * Utiliza "Promise Latching" para dedublicar chamadas simultâneas.
   */
  async getValidToken(): Promise<TokenSet> {
    if (this.isTokenValid()) {
      return this.token!;
    }

    // Se já houver um refresh em andamento, retorna a promise existente (Latching)
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    if (!this.token?.refreshToken) {
      throw new Error("Token expirado e sem refresh token disponível.", {
        cause: "NO_REFRESH_TOKEN",
      });
    }

    // Inicia novo refresh e guarda a promise
    this.refreshPromise = this.performRefresh();

    try {
      const newToken = await this.refreshPromise;
      return newToken;
    } finally {
      // Limpa a promise após conclusão (sucesso ou erro)
      this.refreshPromise = null;
    }
  }

  /**
   * Verifica se o token atual é válido (não expirado)
   */
  private isTokenValid(): boolean {
    if (!this.token) return false;

    const now = Date.now();
    // Considera expirado um pouco antes para segurança (clock tolerance)
    return now < this.token.expiresAt - (this.config.clockToleranceMs || 0);
  }

  /**
   * Executa a lógica real de refresh
   */
  private async performRefresh(): Promise<TokenSet> {
    try {
      console.log("🔄 [TokenManager] Iniciando refresh de token...");
      const newToken = await this.config.refreshTokenFunction(
        this.token!.refreshToken!,
      );

      this.token = newToken;
      console.log("✅ [TokenManager] Token atualizado com sucesso!");
      return newToken;
    } catch (error) {
      console.error("❌ [TokenManager] Falha no refresh de token:", error);
      // Opcional: Limpar token inválido se o erro for fatal (ex: refresh token revogado)
      throw error;
    }
  }

  /**
   * Realiza uma requisição autenticada com retry automático em caso de 401 (Unauthorized)
   *
   * @param requestFn Função que realiza a requisição HTTP.
   *                  Deve aceitar o access token e (opcionalmente) o proof DPoP.
   */
  async authenticatedRequest<T>(
    method: string,
    url: string,
    requestFn: (accessToken: string, dpopProof?: string) => Promise<T>,
  ): Promise<T> {
    // 1. Tenta obter token e fazer a requisição
    try {
      const { accessToken, dpopProof } = await this.prepareRequestCredentials(
        method,
        url,
      );
      return await requestFn(accessToken, dpopProof);
    } catch (error: any) {
      // 2. Intercepta erro 401
      if (this.isUnauthorizedError(error)) {
        console.warn(
          "⚠️ [TokenManager] Erro 401 detectado. Tentando self-healing...",
        );

        // Força refresh (marca token como null ou expirado artificialmente,
        // mas performRefresh já vai pegar o refreshToken atual)
        // Melhor: Invalidar token atual se ele for o mesmo que causou o erro

        // Aqui chamamos getValidToken(). Se o token estava expirado, ele fará refresh.
        // Se o servidor rejeitou mesmo com token "válido" (ex: revogado remotamente),
        // precisamos forçar o refresh.

        // Vamos forçar uma tentativa de refresh ignorando a validade de tempo
        if (!this.refreshPromise) {
          if (!this.token?.refreshToken) throw error; // Não tem como recuperar
          this.refreshPromise = this.performRefresh();
        }

        // Aguarda o refresh (seja o que iniciamos ou um que já estava rodando)
        try {
          await this.refreshPromise!.finally(() => {
            this.refreshPromise = null;
          });
        } catch (refreshErr) {
          throw new Error(
            "Falha no self-healing: Não foi possível atualizar o token.",
            { cause: refreshErr },
          );
        }

        // 3. Replay com novas credenciais
        const { accessToken, dpopProof } = await this.prepareRequestCredentials(
          method,
          url,
        );
        console.log("🔄 [TokenManager] Replay da requisição com novo token...");
        return await requestFn(accessToken, dpopProof);
      }

      throw error;
    }
  }

  /**
   * Prepara credenciais para a requisição (AccessToken e DPoP Proof)
   */
  private async prepareRequestCredentials(method: string, url: string) {
    const tokenSet = await this.getValidToken();
    let dpopProof: string | undefined;

    if (this.config.dpopKeyPair) {
      const proof = await createDPoPProof(this.config.dpopKeyPair, {
        method: method.toUpperCase() as any,
        url,
        accessToken: tokenSet.accessToken,
      });
      dpopProof = proof.jwt;
    }

    return { accessToken: tokenSet.accessToken, dpopProof };
  }

  /**
   * Helper simples para detectar erro 401.
   * Adaptar conforme a lib de HTTP usada (axios, fetch, etc)
   */
  private isUnauthorizedError(error: any): boolean {
    // Verifica status code num Error padrão ou response object
    if (error?.response?.status === 401) return true;
    if (error?.status === 401) return true;
    if (error?.statusCode === 401) return true;
    if (error.message && error.message.includes("401")) return true;
    return false;
  }

  /**
   * Define manualmente o token (ex: login inicial)
   */
  setToken(token: TokenSet) {
    this.token = token;
  }
}
