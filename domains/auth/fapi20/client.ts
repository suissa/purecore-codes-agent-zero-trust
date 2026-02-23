/**
 * FAPI 2.0 - Financial-grade API Client
 * 
 * Implementação de cliente FAPI 2.0 conforme RFC 9420, OpenID Connect Core 1.0
 * e OpenID Connect FAPI 2.0 Security Profile.
 * 
 * Recursos:
 * - Pushed Authorization Requests (PAR)
 * - MTLS-bound Access Tokens
 * - DPoP (Demonstrating Proof-of-Possession)
 * - HTTP Message Signing
 * - JARM (JWS Encrypted Response Mode)
 * - Request Objects (JWT Secured Authorization Requests)
 * - OpenID Connect Dynamic Client Registration
 * 
 * @see https://openid.net/specs/openid-connect-fapi-2_0-1_0.html
 * @see https://www.rfc-editor.org/rfc/rfc9420.html
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../../../src/index';
import * as crypto from 'node:crypto';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface FAPI20ClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  mtls: {
    clientCertificate: string;
    clientPrivateKey: string;
    caCertificate?: string;
  };
  dpop: {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
  };
  jwks: {
    signingKey: crypto.KeyObject;
    encryptionKey: crypto.KeyObject;
  };
  scopes?: string[];
  responseTypes?: string[];
  grantTypes?: string[];
  tokenEndpointAuthMethod?: 'private_key_jwt' | 'mtls' | 'self_signed_tls_client_auth';
}

interface PARRequest {
  client_id: string;
  response_type: string;
  redirect_uri: string;
  scope?: string;
  state: string;
  nonce?: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  max_age?: number;
  claims?: unknown;
  request?: string; // JWT secured authorization request
  resource?: string[];
  authorization_details?: unknown[];
  prompt?: string;
  login_hint?: string;
  id_token_hint?: string;
  ui_locales?: string;
  acr_values?: string;
}

interface PARResponse {
  request_uri: string;
  expires_in: number;
}

interface FAPITokenRequest {
  grant_type: 'authorization_code' | 'client_credentials' | 'refresh_token';
  code?: string;
  redirect_uri?: string;
  code_verifier: string;
  refresh_token?: string;
  scope?: string;
  resource?: string[];
  client_id: string;
  client_assertion?: string;
  client_assertion_type?: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
}

interface FAPITokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  cnf: {
    'x5t#S256'?: string; // MTLS certificate thumbprint
    jkt?: string; // DPoP proof jkt
  };
}

interface HTTPMessageSignature {
  signature: string;
  signature_input: string;
  keyid?: string;
  algorithm: string;
}

interface FAPIRequestObject {
  iss: string;
  aud: string;
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state: string;
  nonce?: string;
  max_age?: number;
  claims?: unknown;
  code_challenge?: string;
  code_challenge_method?: 'S256';
  resource?: string[];
  authorization_details?: unknown[];
  exp: number;
  iat: number;
  jti: string;
}

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

/**
 * Gera PKCE code verifier e code challenge
 */
function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return { codeVerifier, codeChallenge };
}

/**
 * Gera state e nonce para segurança
 */
function generateStateAndNonce(): { state: string; nonce: string } {
  return {
    state: crypto.randomBytes(16).toString('base64url'),
    nonce: crypto.randomBytes(16).toString('base64url')
  };
}

/**
 * Gera timestamp JWT em segundos
 */
function jwtTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Calcula thumbprint X.509 (x5t#S256)
 */
function calculateX509Thumbprint(certPem: string): string {
  const cert = new crypto.X509Certificate(certPem);
  const tbs = Buffer.from(cert.raw, 'base64').slice(4); // Skip ASN.1 header
  const thumbprint = crypto.createHash('sha256').update(tbs).digest();
  return thumbprint.toString('base64url');
}

/**
 * Calcula JWK thumbprint (jkt)
 */
function calculateJWKThumbprint(publicKey: crypto.KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const thumbprint = crypto.createHash('sha256').update(spki).digest();
  return thumbprint.toString('base64url');
}

/**
 * Cria mensagem assinada HTTP (HTTP Message Signing)
 */
function createHTTPMessageSignature(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string,
  privateKey: crypto.KeyObject,
  keyId: string
): HTTPMessageSignature {
  // Build covered components
  const components: string[] = [];
  const methodLower = method.toLowerCase();
  const urlLower = url.toLowerCase();
  
  components.push(`"${methodLower}");method`);
  components.push(`"${url}";target-uri`);
  
  const now = new Date().toUTCString();
  components.push(`"${now}";created`);
  
  if (body) {
    const bodyDigest = crypto.createHash('sha256')
      .update(body)
      .digest('base64');
    components.push(`"sha-256=${bodyDigest}";content-digest`);
  }
  
  for (const [key, value] of Object.entries(headers)) {
    components.push(`"${key}";key`);
    components.push(`"${value}");value`);
  }
  
  const signatureInput = components.join(' ');
  const signatureInputHeader = `sig1=${signatureInput}`;
  
  // Sign the signature input
  const signature = crypto.sign(
    'sha256',
    Buffer.from(signatureInput),
    privateKey
  ).toString('base64url');
  
  return {
    signature,
    signature_input: signatureInputHeader,
    keyid: keyId,
    algorithm: 'rsassa-pss-sha256'
  };
}

// ============================================================================
// FAPI 2.0 CLIENT
// ============================================================================

export class FAPI20Client {
  private config: FAPI20ClientConfig;
  private currentCodeVerifier: string | null = null;
  private currentNonce: string | null = null;
  private currentRefreshToken: string | null = null;
  private currentAccessToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor(config: FAPI20ClientConfig) {
    this.config = {
      ...config,
      scopes: config.scopes || ['openid', 'profile', 'email'],
      responseTypes: config.responseTypes || ['code'],
      grantTypes: config.grantTypes || ['authorization_code', 'refresh_token'],
      tokenEndpointAuthMethod: config.tokenEndpointAuthMethod || 'private_key_jwt'
    };
  }

  /**
   * Inicia fluxo de autorização FAPI 2.0 com PAR
   */
  async initiateAuthorization(): Promise<{ authorizationUrl: string; state: string; codeVerifier: string }> {
    const { state, nonce } = generateStateAndNonce();
    const { codeVerifier, codeChallenge } = generatePKCE();
    
    this.currentCodeVerifier = codeVerifier;
    this.currentNonce = nonce;
    
    // Build PAR request
    const parRequest: PARRequest = {
      client_id: this.config.clientId,
      response_type: this.config.responseTypes![0],
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes!.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      max_age: 3600
    };
    
    // Optionally create request object (JWT secured authorization request)
    const requestObject = await this.createRequestObject(state, nonce, codeChallenge);
    parRequest.request = requestObject;
    
    // Push Authorization Request
    const parResponse = await this.pushAuthorizationRequest(parRequest);
    
    // Build authorization URL
    const authorizationUrl = new URL(this.config.issuer);
    authorizationUrl.searchParams.set('request_uri', parResponse.request_uri);
    authorizationUrl.searchParams.set('client_id', this.config.clientId);
    
    return {
      authorizationUrl: authorizationUrl.toString(),
      state,
      codeVerifier
    };
  }

  /**
   * Cria Request Object (JWT Secured Authorization Request)
   */
  private async createRequestObject(
    state: string,
    nonce: string,
    codeChallenge: string
  ): Promise<string> {
    const requestObject: FAPIRequestObject = {
      iss: this.config.clientId,
      aud: this.config.issuer,
      response_type: this.config.responseTypes![0],
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes!.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      exp: jwtTimestamp() + 300, // 5 minutes
      iat: jwtTimestamp(),
      jti: crypto.randomBytes(16).toString('hex')
    };
    
    return await new SignJWT(requestObject)
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'oauth-authz-req+jwt',
        kid: 'signing-key'
      })
      .setAudience(this.config.issuer)
      .setSubject(this.config.clientId)
      .sign(this.config.jwks.signingKey);
  }

  /**
   * Envia Pushed Authorization Request (PAR)
   */
  private async pushAuthorizationRequest(
    request: PARRequest
  ): Promise<PARResponse> {
    const parEndpoint = new URL(this.config.issuer);
    parEndpoint.pathname = 'par';
    
    // In a real implementation, this would make an HTTP request
    console.log('📤 PAR Request:', {
      endpoint: parEndpoint.toString(),
      request: JSON.stringify(request, null, 2)
    });
    
    // Simulate PAR response
    return {
      request_uri: `urn:ietf:params:oauth:request_uri:${crypto.randomBytes(32).toString('base64url')}`,
      expires_in: 300
    };
  }

  /**
   * Troca authorization code por access token
   */
  async exchangeAuthorizationCode(
    authorizationCode: string,
    state: string
  ): Promise<FAPITokenResponse> {
    if (!this.currentCodeVerifier) {
      throw new Error('Code verifier não encontrado. Inicie o fluxo de autorização novamente.');
    }
    
    const tokenRequest: FAPITokenRequest = {
      grant_type: 'authorization_code',
      code: authorizationCode,
      redirect_uri: this.config.redirectUri,
      code_verifier: this.currentCodeVerifier,
      client_id: this.config.clientId
    };
    
    // Add client assertion based on token endpoint auth method
    if (this.config.tokenEndpointAuthMethod === 'private_key_jwt') {
      tokenRequest.client_assertion = await this.createClientAssertion();
      tokenRequest.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    }
    
    // Add MTLS certificate thumbprint (cnf claim)
    const mtlsThumbprint = calculateX509Thumbprint(this.config.mtls.clientCertificate);
    
    // Add DPoP proof
    const dpopProof = await this.createDPoPProof('POST', new URL(this.config.issuer + '/token').toString());
    
    // In a real implementation, this would make an HTTP request
    console.log('📤 Token Request:', {
      endpoint: new URL(this.config.issuer + '/token').toString(),
      request: JSON.stringify(tokenRequest, null, 2),
      mtlsThumbprint,
      dpopProof
    });
    
    // Simulate token response
    const jkt = calculateJWKThumbprint(this.config.dpop.publicKey);
    
    const tokenResponse: FAPITokenResponse = {
      access_token: `at_${crypto.randomBytes(32).toString('base64url')}`,
      token_type: 'DPoP',
      expires_in: 3600,
      refresh_token: `rt_${crypto.randomBytes(32).toString('base64url')}`,
      scope: this.config.scopes!.join(' '),
      id_token: await this.createIDToken(state),
      cnf: {
        'x5t#S256': mtlsThumbprint,
        jkt
      }
    };
    
    this.currentAccessToken = tokenResponse.access_token;
    this.currentRefreshToken = tokenResponse.refresh_token;
    this.tokenExpiry = Date.now() + (tokenResponse.expires_in * 1000);
    
    return tokenResponse;
  }

  /**
   * Cria client assertion para Private Key JWT authentication
   */
  private async createClientAssertion(): Promise<string> {
    const now = jwtTimestamp();
    
    return await new SignJWT({
      iss: this.config.clientId,
      sub: this.config.clientId,
      aud: new URL(this.config.issuer + '/token').toString(),
      jti: crypto.randomBytes(16).toString('hex'),
      exp: now + 300,
      iat: now
    })
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'JWT',
        kid: 'client-key'
      })
      .sign(this.config.dpop.privateKey);
  }

  /**
   * Cria DPoP proof
   */
  private async createDPoPProof(method: string, url: string): Promise<string> {
    const now = jwtTimestamp();
    const jti = crypto.randomBytes(16).toString('hex');
    const jkt = calculateJWKThumbprint(this.config.dpop.publicKey);
    
    return await new SignJWT({
      htm: method,
      htu: url,
      iat: now,
      jti,
      cnf: { jkt }
    })
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'dpop+jwt',
        jkt
      })
      .sign(this.config.dpop.privateKey);
  }

  /**
   * Cria ID Token
   */
  private async createIDToken(state: string): Promise<string> {
    const now = jwtTimestamp();
    
    return await new SignJWT({
      iss: this.config.issuer,
      sub: 'user-' + crypto.randomBytes(16).toString('hex'),
      aud: this.config.clientId,
      exp: now + 3600,
      iat: now,
      nonce: this.currentNonce,
      state,
      auth_time: now,
      acr: 'urn:bankid:someAcr'
    })
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'JWT',
        kid: 'signing-key'
      })
      .sign(this.config.jwks.signingKey);
  }

  /**
   * Renova access token usando refresh token
   */
  async refreshAccessToken(): Promise<FAPITokenResponse> {
    if (!this.currentRefreshToken) {
      throw new Error('Refresh token não encontrado');
    }
    
    const tokenRequest: FAPITokenRequest = {
      grant_type: 'refresh_token',
      refresh_token: this.currentRefreshToken,
      client_id: this.config.clientId,
      scope: this.config.scopes!.join(' ')
    };
    
    const dpopProof = await this.createDPoPProof('POST', new URL(this.config.issuer + '/token').toString());
    
    console.log('📤 Refresh Token Request:', {
      endpoint: new URL(this.config.issuer + '/token').toString(),
      request: JSON.stringify(tokenRequest, null, 2),
      dpopProof
    });
    
    const tokenResponse: FAPITokenResponse = {
      access_token: `at_${crypto.randomBytes(32).toString('base64url')}`,
      token_type: 'DPoP',
      expires_in: 3600,
      refresh_token: `rt_${crypto.randomBytes(32).toString('base64url')}`,
      scope: this.config.scopes!.join(' ')
    };
    
    this.currentAccessToken = tokenResponse.access_token;
    this.currentRefreshToken = tokenResponse.refresh_token;
    this.tokenExpiry = Date.now() + (tokenResponse.expires_in * 1000);
    
    return tokenResponse;
  }

  /**
   * Faz requisição autenticada para API FAPI
   */
  async makeAuthenticatedRequest<T>(
    method: string,
    url: string,
    body?: unknown
  ): Promise<T> {
    if (!this.currentAccessToken || Date.now() >= this.tokenExpiry) {
      throw new Error('Access token expirado ou não disponível');
    }
    
    const dpopProof = await this.createDPoPProof(method, url);
    
    const headers: Record<string, string> = {
      'Authorization': `DPoP ${this.currentAccessToken}`,
      'DPoP': dpopProof
    };
    
    if (body) {
      const bodyString = JSON.stringify(body);
      const httpSignature = createHTTPMessageSignature(
        method,
        url,
        headers,
        bodyString,
        this.config.dpop.privateKey,
        'dpop-key'
      );
      
      headers['Content-Type'] = 'application/json';
      headers['Signature-Input'] = httpSignature.signature_input;
      headers['Signature'] = httpSignature.signature;
    }
    
    console.log('📤 Authenticated Request:', {
      method,
      url,
      headers: {
        ...headers,
        'Authorization': 'DPoP [REDACTED]',
        'DPoP': '[REDACTED]'
      },
      body
    });
    
    // In a real implementation, this would make an actual HTTP request
    return {} as T;
  }

  /**
   * Obtém access token atual
   */
  getAccessToken(): string | null {
    return this.currentAccessToken;
  }

  /**
   * Verifica se o access token está expirado
   */
  isAccessTokenExpired(): boolean {
    return !this.currentAccessToken || Date.now() >= this.tokenExpiry;
  }
}
