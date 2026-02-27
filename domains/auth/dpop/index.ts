import * as crypto from 'node:crypto';
import { SignJWT, jwtVerify, base64UrlEncode } from '../../../src/index';

export type DPoPKeyType = 'EC' | 'OKP';
export type DPoPAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'EdDSA';

export interface DPoPKeyPair {
  keyId: string;
  keyType: DPoPKeyType;
  algorithm: DPoPAlgorithm;
  publicKeyJWK: DPoPJWK;
  privateKey: crypto.KeyObject;
}

export interface DPoPJWK {
  kty: DPoPKeyType;
  crv?: string;
  x?: string;
  y?: string;
  kid: string;
  alg: DPoPAlgorithm;
  use?: 'sig';
}

export interface DPoPProofPayload {
  jti: string;
  htm: DPoPHttpMethod;
  ht: 'https';
  ath: string;
  iat: number;
  nonce?: string;
  [key: string]: any;
}

export interface DPoPHttpMethod {
  GET: 'GET';
  POST: 'POST';
  PUT: 'PUT';
  PATCH: 'PATCH';
  DELETE: 'DELETE';
}

export const DPoPHttpMethods = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  PATCH: 'PATCH',
  DELETE: 'DELETE',
} as const;

export type DPoPHttpMethod = typeof DPoPHttpMethods[keyof typeof DPoPHttpMethods];

export interface DPoPProof {
  header: {
    alg: DPoPAlgorithm;
    typ: 'dpop+jwt';
    jwk: DPoPJWK;
    kid: string;
  };
  payload: DPoPProofPayload;
  jwt: string;
}

export interface DPoPVerificationResult {
  valid: boolean;
  error?: string;
  proof?: DPoPProof;
  payload?: DPoPProofPayload;
  boundAccessToken?: boolean;
}

export interface DPoPVerifyOptions {
  issuer?: string | string[];
  audience?: string | string[];
  algorithms?: DPoPAlgorithm[];
  clockTolerance?: number;
  requireAth?: boolean;
  requireNonce?: boolean;
  expectedNonce?: string;
  maxTokenAge?: string | number;
}

const DPoP_HEADER: DPoPProof['header'] = {
  alg: 'ES256',
  typ: 'dpop+jwt',
  jwk: {} as DPoPJWK,
  kid: '',
};

export function generateDPoPKeyPair(
  algorithm: DPoPAlgorithm = 'ES256',
  keyId?: string
): DPoPKeyPair {
  const kid = keyId || crypto.randomUUID();

  switch (algorithm) {
    case 'ES256': {
      const ecKeyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const publicKey = crypto.createPublicKey(ecKeyPair.publicKey);
      const publicKeyJWK = publicKey.export({ format: 'jwk' }) as any;

      const privateKey = crypto.createPrivateKey({
        key: ecKeyPair.privateKey,
        format: 'pem',
      });

      return {
        keyId: kid,
        keyType: 'EC' as const,
        algorithm,
        publicKeyJWK: {
          kty: publicKeyJWK.kty,
          crv: 'P-256',
          x: publicKeyJWK.x,
          y: publicKeyJWK.y,
          kid,
          alg: 'ES256' as const,
          use: 'sig' as const,
        },
        privateKey,
      };
    }

    case 'ES384': {
      const ecKeyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-384',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const publicKey = crypto.createPublicKey(ecKeyPair.publicKey);
      const publicKeyJWK = publicKey.export({ format: 'jwk' }) as any;

      const privateKey = crypto.createPrivateKey({
        key: ecKeyPair.privateKey,
        format: 'pem',
      });

      return {
        keyId: kid,
        keyType: 'EC' as const,
        algorithm,
        publicKeyJWK: {
          kty: publicKeyJWK.kty,
          crv: 'P-384',
          x: publicKeyJWK.x,
          y: publicKeyJWK.y,
          kid,
          alg: 'ES384' as const,
          use: 'sig' as const,
        },
        privateKey,
      };
    }

    case 'ES512': {
      const ecKeyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-521',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const publicKey = crypto.createPublicKey(ecKeyPair.publicKey);
      const publicKeyJWK = publicKey.export({ format: 'jwk' }) as any;

      const privateKey = crypto.createPrivateKey({
        key: ecKeyPair.privateKey,
        format: 'pem',
      });

      return {
        keyId: kid,
        keyType: 'EC' as const,
        algorithm,
        publicKeyJWK: {
          kty: publicKeyJWK.kty,
          crv: 'P-521',
          x: publicKeyJWK.x,
          y: publicKeyJWK.y,
          kid,
          alg: 'ES512' as const,
          use: 'sig' as const,
        },
        privateKey,
      };
    }

    case 'EdDSA': {
      const okpKeyPair = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const publicKeyJWK = {
        kty: 'OKP' as const,
        crv: 'Ed25519' as const,
        x: Buffer.from(okpKeyPair.publicKey.slice(-32)).toString('base64url'),
        kid,
        alg: 'EdDSA' as const,
        use: 'sig' as const,
      };

      const privateKey = crypto.createPrivateKey({
        key: okpKeyPair.privateKey,
        format: 'pem',
      });

      return {
        keyId: kid,
        keyType: 'OKP' as const,
        algorithm,
        publicKeyJWK,
        privateKey,
      };
    }

    default:
      throw new Error(`Unsupported DPoP algorithm: ${algorithm}`);
  }
}

export function jwkToCryptoKey(jwk: DPoPJWK): crypto.KeyObject {
  if (jwk.kty === 'EC') {
    return crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
      },
      format: 'jwk',
    });
  }

  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return crypto.createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: jwk.x,
      },
      format: 'jwk',
    });
  }

  throw new Error(`Unsupported JWK type: ${jwk.kty}`);
}

export async function createDPoPProof(
  keyPair: DPoPKeyPair,
  options: {
    method: DPoPHttpMethod;
    url: string;
    accessToken?: string;
    nonce?: string;
    timestamp?: number;
    jti?: string;
  }
): Promise<DPoPProof> {
  const now = Math.floor((options.timestamp || Date.now()) / 1000);
  const jti = options.jti || crypto.randomUUID();

  const payload: DPoPProofPayload = {
    jti,
    htm: options.method,
    ht: 'https',
    iat: now,
  };

  if (options.accessToken) {
    payload.ath = computeAccessTokenHash(options.accessToken);
  }

  if (options.nonce) {
    payload.nonce = options.nonce;
  }

  const header = {
    alg: keyPair.algorithm,
    typ: 'dpop+jwt',
    jwk: keyPair.publicKeyJWK,
    kid: keyPair.keyId,
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(keyPair.privateKey);

  return {
    header,
    payload,
    jwt,
  };
}

export function computeAccessTokenHash(accessToken: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(accessToken);
  const digest = hash.digest();
  return base64UrlEncode(digest);
}

export async function verifyDPoPProof(
  proofJwt: string,
  options: DPoPVerifyOptions
): Promise<DPoPVerificationResult> {
  const startTime = Date.now();

  try {
    const parts = proofJwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid DPoP proof format' };
    }

    const [encodedHeader, encodedPayload] = parts;
    const header = JSON.parse(
      Buffer.from(encodedHeader, 'base64url').toString('utf-8')
    ) as DPoPProof['header'];

    if (header.typ !== 'dpop+jwt') {
      return { valid: false, error: 'Invalid typ claim, expected dpop+jwt' };
    }

    const allowedAlgs = options.algorithms || ['ES256', 'ES384', 'ES512', 'EdDSA'];
    if (!allowedAlgs.includes(header.alg)) {
      return {
        valid: false,
        error: `Algorithm not allowed: ${header.alg}`,
      };
    }

    const publicKey = jwkToCryptoKey(header.jwk);

    const verifyOptions: any = {
      algorithms: allowedAlgs,
      ...options,
    };
    delete verifyOptions.requireAth;
    delete verifyOptions.requireNonce;
    delete verifyOptions.expectedNonce;

    const { payload } = await jwtVerify(proofJwt, publicKey, verifyOptions);

    if (payload.ht !== 'https') {
      return { valid: false, error: 'Invalid ht claim, expected https' };
    }

    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(payload.htm)) {
      return { valid: false, error: 'Invalid htm claim' };
    }

    const now = Math.floor(Date.now() / 1000);
    const clockTolerance = options.clockTolerance || 0;

    if (payload.iat < now - clockTolerance - 300) {
      return { valid: false, error: 'DPoP proof issued too far in the past' };
    }

    if (payload.exp && payload.iat > payload.exp) {
      return { valid: false, error: 'Invalid iat/exp claims' };
    }

    if (options.requireAth && !payload.ath) {
      return { valid: false, error: 'Missing ath claim (access token binding required)' };
    }

    if (options.expectedNonce && payload.nonce !== options.expectedNonce) {
      return {
        valid: false,
        error: `Invalid nonce, expected ${options.expectedNonce}`,
      };
    }

    if (!options.expectedNonce && payload.nonce && typeof payload.nonce === 'string') {
      if (payload.nonce.length < 8) {
        return { valid: false, error: 'Invalid nonce format' };
      }
    }

    const proof: DPoPProof = {
      header,
      payload: payload as DPoPProofPayload,
      jwt: proofJwt,
    };

    const verificationTime = (Date.now() - startTime) / 1000;

    return {
      valid: true,
      proof,
      payload: payload as DPoPProofPayload,
      boundAccessToken: !!payload.ath,
    };
  } catch (error) {
    const err = error as Error;
    return {
      valid: false,
      error: err.message || 'DPoP proof verification failed',
    };
  }
}

export function createDPoPAuthHeader(
  accessToken: string,
  dpopProof: string
): string {
  return `DPoP ${accessToken}, dpop="${dpopProof}"`;
}

export function parseDPoPAuthHeader(
  authHeader: string
): { accessToken: string; dpopProof: string } | null {
  const trimmed = authHeader.trim();

  if (!trimmed.startsWith('DPoP ')) {
    return null;
  }

  const content = trimmed.substring(5).trim();

  const tokenMatch = content.match(/^([^,]+), dpop="([^"]+)"$/);
  if (!tokenMatch) {
    return null;
  }

  const accessToken = tokenMatch[1].trim();
  const dpopProof = tokenMatch[2];

  if (!accessToken || !dpopProof) {
    return null;
  }

  return { accessToken, dpopProof };
}

export function createDPoPBinding(
  accessToken: string,
  dpopProof: string
): string {
  const ath = computeAccessTokenHash(accessToken);
  return `${ath}.${crypto.createHmac('sha256', dpopProof).update(ath).digest('hex')}`;
}

export function verifyDPoPBinding(
  accessToken: string,
  dpopProof: string,
  binding: string
): boolean {
  const ath = computeAccessTokenHash(accessToken);
  const expectedBinding = `${ath}.${crypto.createHmac('sha256', dpopProof).update(ath).digest('hex')}`;
  return binding === expectedBinding;
}

export interface DPoPNonceManager {
  nonces: Map<string, { nonce: string; expiresAt: number }>;
  ttlSeconds: number;
}

export function createNonceManager(ttlSeconds: number = 300): DPoPNonceManager {
  return {
    nonces: new Map(),
    ttlSeconds,
  };
}

export function generateNonce(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function issueNonce(
  manager: DPoPNonceManager,
  clientId: string
): string {
  const nonce = generateNonce();
  const expiresAt = Date.now() + manager.ttlSeconds * 1000;
  manager.nonces.set(clientId, { nonce, expiresAt });
  return nonce;
}

export function validateNonce(
  manager: DPoPNonceManager,
  clientId: string,
  nonce: string
): boolean {
  const entry = manager.nonces.get(clientId);
  if (!entry) return false;

  if (Date.now() > entry.expiresAt) {
    manager.nonces.delete(clientId);
    return false;
  }

  if (entry.nonce !== nonce) {
    return false;
  }

  manager.nonces.delete(clientId);
  return true;
}

export function cleanupExpiredNonces(manager: DPoPNonceManager): number {
  const now = Date.now();
  let cleaned = 0;

  for (const [clientId, entry] of manager.nonces.entries()) {
    if (now > entry.expiresAt) {
      manager.nonces.delete(clientId);
      cleaned++;
    }
  }

  return cleaned;
}
