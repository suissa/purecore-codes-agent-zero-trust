/**
 * Módulo de Autenticação - JWT, DPoP (RFC 9449), Token Manager
 */

import * as crypto from 'node:crypto';
import { computeJWKThumbprint, publicKeyToJWK, type JWK } from '../crypto';

// ============================================================================
// Tipos JWT
// ============================================================================

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface JWTHeaderParameters {
  alg?: string;
  typ?: string;
  kid?: string;
  jwk?: JWK;
  [key: string]: any;
}

export interface JWTVerifyResult {
  payload: JWTPayload;
  protectedHeader: JWTHeaderParameters;
}

export interface JWTVerifyOptions {
  issuer?: string | string[];
  audience?: string | string[];
  algorithms?: string[];
  currentDate?: Date;
  maxTokenAge?: string | number;
}

// ============================================================================
// Tipos DPoP
// ============================================================================

export type DPoPAlgorithm = 'EdDSA' | 'ES256' | 'ES384' | 'ES512';

export interface DPoPKeyPair {
  keyId: string;
  keyType: 'OKP' | 'EC';
  algorithm: DPoPAlgorithm;
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
  publicKeyJWK: JWK;
}

export interface DPoPProofPayload {
  jti: string;
  htm: string;
  ht: string;
  iat: number;
  ath?: string;
  nonce?: string;
  cnf?: {
    jwk: JWK;
    signal_identity_kid?: string;
  };
  [key: string]: any;
}

export interface DPoPProof {
  jwt: string;
  header: JWTHeaderParameters;
  payload: DPoPProofPayload;
}

export interface DPoPVerificationResult {
  valid: boolean;
  error?: string;
  proof?: DPoPProof;
  boundAccessToken?: string;
  bindingId?: string;
}

export interface DPoPServerConfig {
  algorithms?: DPoPAlgorithm[];
  requireAth?: boolean;
  requireHtm?: boolean;
  requireHt?: boolean;
  nonceTtlSeconds?: number;
  audience?: string;
}

export type DPoPHttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

export const DPoPHttpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'] as const;

// ============================================================================
// Utilitários
// ============================================================================



function base64UrlEncode(input: Uint8Array | string | object): string {
  let buffer: Buffer;
  if (typeof input === 'string') {
    buffer = Buffer.from(input, 'utf-8');
  } else if (input instanceof Uint8Array) {
    buffer = Buffer.from(input);
  } else {
    buffer = Buffer.from(JSON.stringify(input), 'utf-8');
  }
  return buffer.toString('base64url');
}

function base64UrlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf-8');
}

function parseTime(time: string | number | undefined): number {
  if (typeof time === 'number') return time;
  if (!time) return 0;

  const regex = /^(\d+)([smhdwy])$/;
  const match = time.match(regex);
  if (!match || !match[1] || !match[2]) throw new Error(`Formato de tempo inválido: ${time}`);

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    case 'w': return value * 7 * 24 * 60 * 60;
    case 'y': return value * 365.25 * 24 * 60 * 60;
    default: return value;
  }
}

// ============================================================================
// JWT Sign/Verify
// ============================================================================

export class SignJWT {
  private _payload: JWTPayload;
  private _protectedHeader: JWTHeaderParameters = { alg: 'EdDSA', typ: 'JWT' };

  constructor(payload: JWTPayload) {
    this._payload = { ...payload };
  }

  setProtectedHeader(protectedHeader: JWTHeaderParameters): this {
    this._protectedHeader = { ...this._protectedHeader, ...protectedHeader };
    return this;
  }

  setIssuer(issuer: string): this {
    this._payload.iss = issuer;
    return this;
  }

  setSubject(subject: string): this {
    this._payload.sub = subject;
    return this;
  }

  setAudience(audience: string | string[]): this {
    this._payload.aud = audience;
    return this;
  }

  setJti(jwtId: string): this {
    this._payload.jti = jwtId;
    return this;
  }

  setNotBefore(input: number | string): this {
    const now = Math.floor(Date.now() / 1000);
    this._payload.nbf = now + parseTime(input);
    return this;
  }

  setIssuedAt(input?: number): this {
    this._payload.iat = input ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setExpirationTime(input: number | string): this {
    const now = this._payload.iat ?? Math.floor(Date.now() / 1000);
    if (typeof input === 'string') {
      this._payload.exp = now + parseTime(input);
    } else {
      this._payload.exp = input > 10000000000 ? input : now + input;
    }
    return this;
  }

  async sign(privateKey: crypto.KeyObject | string): Promise<string> {
    const keyObj = typeof privateKey === 'string' 
      ? crypto.createPrivateKey(privateKey) 
      : privateKey;

    const encodedHeader = base64UrlEncode(this._protectedHeader);
    const encodedPayload = base64UrlEncode(this._payload);
    const data = `${encodedHeader}.${encodedPayload}`;

    const signature = crypto.sign(null, Buffer.from(data), keyObj);
    const encodedSignature = base64UrlEncode(signature);

    return `${data}.${encodedSignature}`;
  }
}

export async function jwtVerify(
  jwt: string,
  key: crypto.KeyObject | string,
  options?: JWTVerifyOptions
): Promise<JWTVerifyResult> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('JWT inválido: Formato deve ser header.payload.signature');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const data = `${encodedHeader}.${encodedPayload}`;

  const publicKey = typeof key === 'string' 
    ? crypto.createPublicKey(key) 
    : key;

  const verified = crypto.verify(
    null,
    Buffer.from(data),
    publicKey,
    Buffer.from(encodedSignature, 'base64url')
  );

  if (!verified) {
    throw new Error('Assinatura do JWT inválida');
  }

  const protectedHeader = JSON.parse(base64UrlDecode(encodedHeader)) as JWTHeaderParameters;
  const payload = JSON.parse(base64UrlDecode(encodedPayload)) as JWTPayload;

  const now = options?.currentDate
    ? Math.floor(options.currentDate.getTime() / 1000)
    : Math.floor(Date.now() / 1000);

  if (payload.exp && now > payload.exp) {
    throw new Error(`Token expirado (exp). Expirou em ${new Date(payload.exp * 1000).toISOString()}`);
  }

  if (payload.nbf && now < payload.nbf) {
    throw new Error(`Token ainda não ativo (nbf). Válido a partir de ${new Date(payload.nbf * 1000).toISOString()}`);
  }

  if (options?.issuer) {
    const issuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    if (!payload.iss || !issuers.includes(payload.iss)) {
      throw new Error(`Issuer inválido. Esperado: ${issuers.join(' ou ')}, Recebido: ${payload.iss}`);
    }
  }

  if (options?.audience) {
    const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
    const payloadAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const hasValidAud = payloadAud.some(a => a && audiences.includes(a));
    if (!hasValidAud) {
      throw new Error(`Audience inválida`);
    }
  }

  if (options?.maxTokenAge && payload.iat) {
    const maxAge = parseTime(options.maxTokenAge);
    if (now - payload.iat > maxAge) {
      throw new Error(`Token excedeu a idade máxima permitida de ${options.maxTokenAge}`);
    }
  }

  return { payload, protectedHeader };
}

export function generateKeyPair(algorithm: 'EdDSA' | 'ES256' = 'EdDSA') {
  // Mapeia algoritmos para nomes que o Node.js reconhece
  const algoMap: Record<string, string> = {
    'EdDSA': 'ed25519',
    'ES256': 'ec',
  };
  const nodeAlgo = algoMap[algorithm] || 'ed25519';
  
  if (nodeAlgo === 'ec') {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
  }
  
  return crypto.generateKeyPairSync(nodeAlgo as any);
}

// ============================================================================
// DPoP Functions
// ============================================================================

/**
 * Gera par de chaves para DPoP
 */
export function generateDPoPKeyPair(algorithm: DPoPAlgorithm = 'EdDSA'): DPoPKeyPair {
  const { publicKey, privateKey } = generateKeyPair(algorithm as any);
  
  const keyId = crypto.randomBytes(16).toString('base64url');
  
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const publicKeyBytes = publicKeyDer.slice(-32);
  
  const jwk: JWK = {
    kty: algorithm === 'EdDSA' ? 'OKP' : 'EC',
    crv: algorithm === 'EdDSA' ? 'Ed25519' : 'P-256',
    x: publicKeyBytes.toString('base64url')
  };

  return {
    keyId,
    keyType: algorithm === 'EdDSA' ? 'OKP' : 'EC',
    algorithm,
    publicKey,
    privateKey,
    publicKeyJWK: jwk
  };
}

/**
 * Computa hash do access token para ath claim
 */
export function computeAccessTokenHash(accessToken: string): string {
  return crypto.createHash('sha256').update(accessToken).digest('base64url');
}

/**
 * Cria DPoP Proof
 */
export async function createDPoPProof(
  keyPair: DPoPKeyPair,
  options: {
    method: DPoPHttpMethod;
    url: string;
    accessToken?: string;
    nonce?: string;
    signalIdentityKey?: Uint8Array;
  }
): Promise<DPoPProof> {
  const jti = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  
  const url = new URL(options.url);
  const htu = `${url.protocol}//${url.host}${url.pathname}`;
  
  const payload: DPoPProofPayload = {
    jti,
    htm: options.method.toUpperCase(),
    ht: htu,
    iat: now
  };

  if (options.accessToken) {
    payload.ath = computeAccessTokenHash(options.accessToken);
  }

  if (options.nonce) {
    payload.nonce = options.nonce;
  }

  // Session Context Latching com JWK Thumbprint
  if (options.signalIdentityKey) {
    const signalJWK = publicKeyToJWK(options.signalIdentityKey, 'X25519');
    const signalThumbprint = computeJWKThumbprint(signalJWK);
    payload.cnf = {
      jwk: keyPair.publicKeyJWK,
      signal_identity_kid: signalThumbprint
    };
  }

  const header: JWTHeaderParameters = {
    typ: 'dpop+jwt',
    alg: keyPair.algorithm,
    jwk: keyPair.publicKeyJWK,
    kid: keyPair.keyId
  };

  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const data = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign(null, Buffer.from(data), keyPair.privateKey);
  const encodedSignature = base64UrlEncode(signature);

  return {
    jwt: `${data}.${encodedSignature}`,
    header,
    payload
  };
}

/**
 * Verifica DPoP Proof
 */
export async function verifyDPoPProof(
  jwt: string,
  options?: {
    algorithms?: DPoPAlgorithm[];
    requireAth?: boolean;
    requiredMethod?: DPoPHttpMethod;
    requiredUrl?: string;
  }
): Promise<DPoPVerificationResult> {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Formato JWT inválido' };
    }

    const [encodedHeader, encodedPayload] = parts as [string, string, string];
    const header = JSON.parse(base64UrlDecode(encodedHeader)) as JWTHeaderParameters;
    const payload = JSON.parse(base64UrlDecode(encodedPayload)) as DPoPProofPayload;

    // Validar typ
    if (header.typ !== 'dpop+jwt') {
      return { valid: false, error: 'typ deve ser dpop+jwt' };
    }

    // Validar algoritmo
    const allowedAlgorithms = options?.algorithms || ['EdDSA', 'ES256', 'ES384', 'ES512'];
    if (!header.alg || !allowedAlgorithms.includes(header.alg as DPoPAlgorithm)) {
      return { valid: false, error: `Algoritmo não permitido: ${header.alg}` };
    }

    // Validar jwk no header
    if (!header.jwk) {
      return { valid: false, error: 'jwk ausente no header' };
    }

    // Validar claims obrigatórios
    if (!payload.jti || !payload.htm || !payload.ht || !payload.iat) {
      return { valid: false, error: 'Claims obrigatórios ausentes' };
    }

    if (options?.requireAth && !payload.ath) {
      return { valid: false, error: 'ath claim ausente' };
    }

    if (options?.requiredMethod && payload.htm !== options.requiredMethod.toUpperCase()) {
      return { valid: false, error: `HTTP method mismatch: esperado ${options.requiredMethod}, recebido ${payload.htm}` };
    }

    if (options?.requiredUrl) {
      const expectedUrl = new URL(options.requiredUrl);
      const actualUrl = new URL(payload.ht);
      if (`${expectedUrl.protocol}//${expectedUrl.host}${expectedUrl.pathname}` !== 
          `${actualUrl.protocol}//${actualUrl.host}${actualUrl.pathname}`) {
        return { valid: false, error: 'URL mismatch' };
      }
    }

    // Validar timestamp (5 minutos de tolerância)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > 300) {
      return { valid: false, error: 'Proof expirado ou clock skew excessivo' };
    }

    const result: DPoPVerificationResult = {
      valid: true,
      proof: { jwt, header, payload },
      bindingId: payload.jti
    };
    if (payload.ath !== undefined) {
      result.boundAccessToken = payload.ath;
    }
    return result;

  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Erro na verificação'
    };
  }
}

/**
 * Cria header de autorização DPoP
 */
export function createDPoPAuthHeader(accessToken: string, dpopProof: string): string {
  return `DPoP ${accessToken} dpop=${dpopProof}`;
}

/**
 * Parse header de autorização DPoP
 */
export function parseDPoPAuthHeader(header: string): { accessToken: string; dpopProof: string } | null {
  const match = header.match(/^DPoP\s+(\S+)(?:\s+dpop=(\S+))?$/);
  if (!match || !match[1]) return null;
  
  return {
    accessToken: match[1],
    dpopProof: match[2] || ''
  };
}

// ============================================================================
// Nonce Manager
// ============================================================================

export interface NonceManager {
  nonces: Map<string, Set<string>>;
  ttlSeconds: number;
}

export function generateNonce(): string {
  return crypto.randomBytes(16).toString('base64url');
}

export function createNonceManager(ttlSeconds: number = 300): NonceManager {
  return {
    nonces: new Map(),
    ttlSeconds
  };
}

export function issueNonce(manager: NonceManager, clientId: string): string {
  const nonce = generateNonce();
  
  if (!manager.nonces.has(clientId)) {
    manager.nonces.set(clientId, new Set());
  }
  manager.nonces.get(clientId)!.add(nonce);

  // Limpar nonce após TTL
  setTimeout(() => {
    manager.nonces.get(clientId)?.delete(nonce);
  }, manager.ttlSeconds * 1000);

  return nonce;
}

export function validateNonce(manager: NonceManager, clientId: string, nonce: string): boolean {
  const clientNonces = manager.nonces.get(clientId);
  if (!clientNonces) return false;

  if (!clientNonces.has(nonce)) {
    return false;
  }

  // Consumir nonce (one-time use)
  clientNonces.delete(nonce);
  return true;
}

// ============================================================================
// DPoP Server
// ============================================================================

export class DPoPServer {
  private config: DPoPServerConfig;
  private nonceManager: NonceManager;
  private usedJTI: Map<string, number> = new Map();

  constructor(config: DPoPServerConfig = {}) {
    this.config = {
      algorithms: ['EdDSA', 'ES256', 'ES384', 'ES512'],
      requireAth: true,
      ...config
    };
    this.nonceManager = createNonceManager(config.nonceTtlSeconds || 300);
  }

  async issueNonce(clientId: string): Promise<string> {
    return issueNonce(this.nonceManager, clientId);
  }

  async verifyDPoPAuthHeader(
    authHeader: string,
    options?: {
      requiredMethod?: DPoPHttpMethod;
      requiredUrl?: string;
      audience?: string;
    }
  ): Promise<DPoPVerificationResult> {
    const parsed = parseDPoPAuthHeader(authHeader);
    if (!parsed) {
      return { valid: false, error: 'Header DPoP inválido' };
    }

    const verifyOpts: any = {
      algorithms: this.config.algorithms,
      requireAth: this.config.requireAth
    };
    if (options?.requiredMethod) verifyOpts.requiredMethod = options.requiredMethod;
    if (options?.requiredUrl) verifyOpts.requiredUrl = options.requiredUrl;

    const verification = await verifyDPoPProof(parsed.dpopProof, verifyOpts);

    if (!verification.valid || !verification.proof) {
      return verification;
    }

    // Verificar nonce se presente
    if (verification.proof.payload.nonce) {
      // Em produção, validar contra nonce manager
    }

    // Verificar JTI para replay (em produção, usar store distribuído)
    const now = Math.floor(Date.now() / 1000);
    if (this.usedJTI.has(verification.proof.payload.jti)) {
      return { valid: false, error: 'JTI já utilizado (replay detected)' };
    }
    this.usedJTI.set(verification.proof.payload.jti, now);

    // Limpar JTIs antigos
    for (const [jti, timestamp] of this.usedJTI.entries()) {
      if (now - timestamp > 300) {
        this.usedJTI.delete(jti);
      }
    }

    return verification;
  }
}

// ============================================================================
// Token Manager com Promise Latching
// ============================================================================

export interface TokenData {
  token: string;
  expiresAt: number;
  refreshToken?: string;
}

export interface TokenManagerConfig {
  refreshThresholdSeconds?: number;
  maxRetries?: number;
  baseDelayMs?: number;
}

export class TokenManager {
  private cache: TokenData | null = null;
  private refreshPromise: Promise<string> | null = null;
  private config: Required<TokenManagerConfig>;
  private refreshFn: (() => Promise<TokenData>) | null = null;

  constructor(config: TokenManagerConfig = {}) {
    this.config = {
      refreshThresholdSeconds: 300,
      maxRetries: 3,
      baseDelayMs: 1000,
      ...config
    };
  }

  setRefreshFn(fn: () => Promise<TokenData>): void {
    this.refreshFn = fn;
  }

  async getToken(): Promise<string> {
    if (!this.refreshFn) {
      throw new Error('Refresh function not configured');
    }

    // Verificar cache
    if (this.cache && !this.isExpiringSoon(this.cache)) {
      return this.cache.token;
    }

    // Promise Latching: aguardar refresh existente
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Iniciar novo refresh
    this.refreshPromise = this.refreshWithRetry();

    try {
      const token = await this.refreshPromise;
      return token;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async refreshWithRetry(): Promise<string> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      try {
        const tokenData = await this.refreshFn!();
        this.cache = tokenData;
        return tokenData.token;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Token refresh failed');

        if (attempt < this.config.maxRetries - 1) {
          const delay = this.config.baseDelayMs * Math.pow(2, attempt);
          const jitter = delay * 0.1 * (Math.random() - 0.5);
          await this.sleep(delay + jitter);
        }
      }
    }

    throw lastError || new Error('Token refresh failed after all retries');
  }

  private isExpiringSoon(tokenData: TokenData): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now + this.config.refreshThresholdSeconds >= tokenData.expiresAt;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  clearCache(): void {
    this.cache = null;
  }
}

// ============================================================================
// Circuit Breaker
// ============================================================================

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerConfig {
  threshold?: number;
  resetTimeout?: number;
  monitoringPeriod?: number;
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private failures = 0;
  private successes = 0;
  private lastFailureTime = 0;
  private config: Required<CircuitBreakerConfig>;

  constructor(config: CircuitBreakerConfig = {}) {
    this.config = {
      threshold: 5,
      resetTimeout: 30000,
      monitoringPeriod: 10000,
      ...config
    };
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime < this.config.resetTimeout) {
        throw new CircuitOpenError('Circuit breaker aberto');
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.successes++;
      if (this.successes >= 3) {
        this.state = 'CLOSED';
        this.successes = 0;
      }
    }
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();
    if (this.failures >= this.config.threshold) {
      this.state = 'OPEN';
      this.successes = 0;
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  reset(): void {
    this.state = 'CLOSED';
    this.failures = 0;
    this.successes = 0;
  }
}

export class CircuitOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CircuitOpenError';
  }
}
