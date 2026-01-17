/**
 * Tipo semântico para tokens Bearer de autenticação
 * Garante formato correto e segurança básica
 */

import { Brand, STAMP } from "../../../src/semantic/shim";
import {
  DPoPKeyPair,
  DPoPProof,
  DPoPHttpMethod,
  DPoPNonceManager,
  createNonceManager,
  createDPoPProof,
  verifyDPoPProof,
  generateDPoPKeyPair,
  createDPoPAuthHeader,
  parseDPoPAuthHeader,
  issueNonce,
  validateNonce,
  computeAccessTokenHash,
  type DPoPVerificationResult
} from "../dpop";

export type BearerToken = Brand<string, "auth.token.bearer">;

export const BearerToken = (() => {
  const f = STAMP<"auth.token.bearer">();
  
  return {
    of: (v: unknown): BearerToken => {
      const s = String(v).trim();
      
      if (!s) {
        throw new TypeError("Bearer token não pode ser vazio");
      }
      
      if (/\s/.test(s)) {
        throw new TypeError("Bearer token não pode conter espaços");
      }
      
      if (s.length < 16) {
        throw new TypeError("Bearer token deve ter pelo menos 16 caracteres");
      }
      
      if (!/^[A-Za-z0-9\-._~+/]+=*$/.test(s)) {
        throw new TypeError("Bearer token contém caracteres inválidos");
      }
      
      return f.of(s);
    },
    
    un: (v: BearerToken): string => f.un(v),
    
    make: (value: string): BearerToken => BearerToken.of(value),

    toAuthHeader: (v: BearerToken): string => `Bearer ${f.un(v)}`,

    fromAuthHeader: (header: string): BearerToken => {
      const trimmed = header.trim();
      
      if (!trimmed.startsWith('Bearer ')) {
        throw new TypeError("Header de autorização deve começar com 'Bearer '");
      }
      
      const token = trimmed.substring(7);
      return f.of(token);
    },
    
    isJWT: (v: BearerToken): boolean => {
      const token = f.un(v);
      const parts = token.split('.');
      return parts.length === 3 && parts.every(part => part.length > 0);
    },
    
    getJWTPayload: (v: BearerToken): any => {
      if (!BearerToken.isJWT(v)) {
        throw new TypeError("Token não é um JWT válido");
      }
      
      const token = f.un(v);
      const payloadPart = token.split('.')[1];
      
      try {
        const decoded = Buffer.from(payloadPart, 'base64url').toString('utf-8');
        return JSON.parse(decoded);
      } catch (error) {
        throw new TypeError("Não foi possível decodificar payload do JWT");
      }
    },
    
    isJWTExpired: (v: BearerToken): boolean => {
      try {
        const payload = BearerToken.getJWTPayload(v);
        if (!payload.exp) return false;
        
        const now = Math.floor(Date.now() / 1000);
        return payload.exp < now;
      } catch {
        return false;
      }
    },
  };
})();

export type DPoPAuthToken = Brand<string, "auth.token.dpop">;

export interface DPoPAuthTokenData {
  accessToken: string;
  dpopKeyPair: DPoPKeyPair;
  createdAt: number;
  expiresAt: number;
}

export const DPoPAuthToken = (() => {
  const f = STAMP<"auth.token.dpop">();
  
  return {
    of: (value: { accessToken: string; dpopKeyPair: DPoPKeyPair; createdAt: number; expiresAt: number }): DPoPAuthToken => {
      if (!value.accessToken || typeof value.accessToken !== 'string') {
        throw new TypeError("accessToken é obrigatório");
      }
      if (!value.dpopKeyPair || !value.dpopKeyPair.privateKey) {
        throw new TypeError("dpopKeyPair é obrigatório");
      }
      if (!value.createdAt || typeof value.createdAt !== 'number') {
        throw new TypeError("createdAt é obrigatório");
      }
      if (!value.expiresAt || typeof value.expiresAt !== 'number') {
        throw new TypeError("expiresAt é obrigatório");
      }
      if (value.expiresAt <= value.createdAt) {
        throw new TypeError("expiresAt deve ser maior que createdAt");
      }
      
      const serialized = JSON.stringify({
        accessToken: value.accessToken,
        dpopKeyPair: {
          keyId: value.dpopKeyPair.keyId,
          keyType: value.dpopKeyPair.keyType,
          algorithm: value.dpopKeyPair.algorithm,
          publicKeyJWK: value.dpopKeyPair.publicKeyJWK,
        },
        createdAt: value.createdAt,
        expiresAt: value.expiresAt,
      });
      
      return f.of(serialized);
    },
    
    un: (v: DPoPAuthToken): DPoPAuthTokenData => {
      const parsed = JSON.parse(f.un(v));
      const dpopKeyPair = generateDPoPKeyPair(
        parsed.dpopKeyPair.algorithm,
        parsed.dpopKeyPair.keyId
      );
      dpopKeyPair.publicKeyJWK = parsed.dpopKeyPair.publicKeyJWK;
      
      return {
        accessToken: parsed.accessToken,
        dpopKeyPair,
        createdAt: parsed.createdAt,
        expiresAt: parsed.expiresAt,
      };
    },
    
    create: (
      accessToken: string,
      options?: {
        algorithm?: 'ES256' | 'ES384' | 'ES512' | 'EdDSA';
        expiresInMs?: number;
      }
    ): DPoPAuthToken => {
      const algorithm = options?.algorithm || 'ES256';
      const expiresInMs = options?.expiresInMs || 3600000;
      
      const dpopKeyPair = generateDPoPKeyPair(algorithm);
      const createdAt = Date.now();
      const expiresAt = createdAt + expiresInMs;
      
      return DPoPAuthToken.of({
        accessToken,
        dpopKeyPair,
        createdAt,
        expiresAt,
      });
    },
    
    createProof: async (
      v: DPoPAuthToken,
      options: {
        method: DPoPHttpMethod;
        url: string;
        nonce?: string;
        timestamp?: number;
      }
    ): Promise<DPoPProof> => {
      const data = DPoPAuthToken.un(v);
      
      return await createDPoPProof(data.dpopKeyPair, {
        method: options.method,
        url: options.url,
        accessToken: data.accessToken,
        nonce: options.nonce,
        timestamp: options.timestamp,
      });
    },
    
    toDPoPAuthHeader: async (
      v: DPoPAuthToken,
      options: {
        method: DPoPHttpMethod;
        url: string;
        nonce?: string;
      }
    ): Promise<string> => {
      const data = DPoPAuthToken.un(v);
      const proof = await DPoPAuthToken.createProof(v, {
        method: options.method,
        url: options.url,
        nonce: options.nonce,
      });
      
      return createDPoPAuthHeader(data.accessToken, proof.jwt);
    },
    
    isExpired: (v: DPoPAuthToken): boolean => {
      const data = DPoPAuthToken.un(v);
      return Date.now() >= data.expiresAt;
    },
    
    getAccessToken: (v: DPoPAuthToken): string => {
      return DPoPAuthToken.un(v).accessToken;
    },
  };
})();

export interface DPoPClientConfig {
  serverUrl: string;
  clientId: string;
  tokenEndpoint: string;
  algorithm?: 'ES256' | 'ES384' | 'ES512' | 'EdDSA';
  nonceManager?: DPoPNonceManager;
}

export class DPoPClient {
  private config: DPoPClientConfig;
  private currentToken: DPoPAuthToken | null = null;
  private nonceManager: DPoPNonceManager;
  private serverNonce: string | null = null;

  constructor(config: DPoPClientConfig) {
    this.config = {
      algorithm: 'ES256',
      nonceManager: createNonceManager(300),
      ...config,
    };
    this.nonceManager = this.config.nonceManager!;
  }

  async getAccessToken(): Promise<DPoPAuthToken> {
    if (this.currentToken && !DPoPAuthToken.isExpired(this.currentToken)) {
      return this.currentToken;
    }

    return await this.requestAccessToken();
  }

  async getDPoPAuthHeader(
    method: DPoPHttpMethod,
    url: string,
    options?: { nonce?: string }
  ): Promise<string> {
    const token = await this.getAccessToken();
    return await DPoPAuthToken.toDPoPAuthHeader(token, {
      method,
      url,
      nonce: options?.nonce || this.serverNonce || undefined,
    });
  }

  async refreshNonce(): Promise<string> {
    const nonce = generateNonce();
    this.serverNonce = nonce;
    return nonce;
  }

  private async requestAccessToken(): Promise<DPoPAuthToken> {
    const tokenEndpoint = new URL(this.config.tokenEndpoint, this.config.serverUrl).toString();
    
    const dpopKeyPair = generateDPoPKeyPair(this.config.algorithm!);
    
    const proof = await createDPoPProof(dpopKeyPair, {
      method: 'POST',
      url: tokenEndpoint,
    });

    const accessToken = await this.exchangeCodeForToken(tokenEndpoint, proof);

    this.currentToken = DPoPAuthToken.create(accessToken, {
      algorithm: this.config.algorithm,
    });

    if (proof.payload.nonce) {
      this.serverNonce = proof.payload.nonce;
    }

    return this.currentToken;
  }

  private async exchangeCodeForToken(
    tokenEndpoint: string,
    dpopProof: DPoPProof
  ): Promise<string> {
    return `mock-access-token-${crypto.randomUUID()}`;
  }
}

export class DPoPServer {
  private nonceManager: DPoPNonceManager;
  private boundTokens: Map<string, { ath: string; keyId: string; expiresAt: number }>;

  constructor(options?: { nonceTtlSeconds?: number }) {
    this.nonceManager = createNonceManager(options?.nonceTtlSeconds || 300);
    this.boundTokens = new Map();
  }

  async issueNonce(clientId: string): Promise<string> {
    return issueNonce(this.nonceManager, clientId);
  }

  validateNonce(clientId: string, nonce: string): boolean {
    return validateNonce(this.nonceManager, clientId, nonce);
  }

  bindTokenToDPoP(
    accessToken: string,
    dpopProof: DPoPProof,
    options?: { expiresInMs?: number }
  ): string {
    const ath = computeAccessTokenHash(accessToken);
    const keyId = dpopProof.header.kid;
    const expiresInMs = options?.expiresInMs || 3600000;
    const expiresAt = Date.now() + expiresInMs;

    const bindingId = `${ath.substring(0, 16)}.${keyId}`;
    this.boundTokens.set(bindingId, { ath, keyId, expiresAt });

    return bindingId;
  }

  async verifyDPoPAuthHeader(
    authHeader: string,
    options?: {
      requiredMethod?: DPoPHttpMethod;
      requiredUrl?: string;
      issuer?: string;
      audience?: string;
    }
  ): Promise<DPoPVerificationResult & { accessToken?: string; bindingId?: string }> {
    const parsed = parseDPoPAuthHeader(authHeader);
    if (!parsed) {
      return { valid: false, error: 'Invalid DPoP authorization header format' };
    }

    const verificationResult = await verifyDPoPProof(parsed.dpopProof, {
      algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
      issuer: options?.issuer,
      audience: options?.audience,
      requireAth: true,
    });

    if (!verificationResult.valid) {
      return verificationResult as DPoPVerificationResult & { accessToken?: string; bindingId?: string };
    }

    if (options?.requiredMethod && verificationResult.payload?.htm !== options.requiredMethod) {
      return {
        valid: false,
        error: `HTTP method mismatch: expected ${options.requiredMethod}`,
      };
    }

    if (options?.requiredUrl) {
      const url = new URL(options.requiredUrl);
      const ath = verificationResult.payload?.ath;
      
      if (ath) {
        const bindingId = `${ath.substring(0, 16)}.${verificationResult.proof?.header.kid}`;
        const binding = this.boundTokens.get(bindingId);
        
        if (!binding || Date.now() > binding.expiresAt) {
          return {
            valid: false,
            error: 'Access token not bound or binding expired',
          };
        }

        if (binding.ath !== ath) {
          return {
            valid: false,
            error: 'Access token hash mismatch',
          };
        }

        return {
          ...verificationResult,
          accessToken: parsed.accessToken,
          bindingId,
        };
      }
    }

    return {
      ...verificationResult,
      accessToken: parsed.accessToken,
    };
  }

  cleanupExpiredBindings(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [bindingId, binding] of this.boundTokens.entries()) {
      if (now > binding.expiresAt) {
        this.boundTokens.delete(bindingId);
        cleaned++;
      }
    }

    return cleaned;
  }
}