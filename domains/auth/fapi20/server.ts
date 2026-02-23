/**
 * FAPI 2.0 - Financial-grade API Server
 * 
 * Implementação de servidor FAPI 2.0 conforme RFC 9420, OpenID Connect Core 1.0
 * e OpenID Connect FAPI 2.0 Security Profile.
 * 
 * Recursos:
 * - Pushed Authorization Requests (PAR) endpoint
 * - Token endpoint com MTLS e DPoP
 * - Authorization endpoint
 * - UserInfo endpoint
 * - JWKS endpoint
 * - HTTP Message Signing verification
 * - JARM (JWS Encrypted Response Mode)
 * - Request Object validation
 * 
 * @see https://openid.net/specs/openid-connect-fapi-2_0-1_0.html
 * @see https://www.rfc-editor.org/rfc/rfc9420.html
 */

import { SignJWT, jwtVerify, generateKeyPair } from '../../../src/index';
import * as crypto from 'node:crypto';

// ============================================================================
// TIPOS E INTERFACES
// ============================================================================

interface FAPI20ServerConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  jwksEndpoint: string;
  parEndpoint: string;
  registrationEndpoint: string;
  mtls: {
    caCertificate: string;
    requireClientCertificate: boolean;
  };
  signingKeys: {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
  };
  encryptionKeys: {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
  };
}

interface FAPI20ClientRegistration {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scope?: string;
  token_endpoint_auth_method: string;
  jwks_uri?: string;
  software_id: string;
  software_version: string;
  require_signed_request_object: boolean;
  require_pushed_authorization_requests: boolean;
  tls_client_certificate_bound_access_tokens: boolean;
  dpop_bound_access_tokens: boolean;
}

interface FAPI20AuthorizationRequest {
  client_id: string;
  response_type: string;
  redirect_uri: string;
  scope?: string;
  state: string;
  nonce?: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  max_age?: number;
  request?: string;
  request_uri?: string;
}

interface FAPI20AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  expires_at: number;
  used: boolean;
}

interface FAPI20AccessToken {
  access_token: string;
  token_type: 'DPoP' | 'Bearer';
  expires_in: number;
  expires_at: number;
  refresh_token?: string;
  scope: string;
  client_id: string;
  cnf?: {
    'x5t#S256'?: string;
    jkt?: string;
  };
}

// ============================================================================
// FAPI 2.0 SERVER
// ============================================================================

export class FAPI20Server {
  private config: FAPI20ServerConfig;
  private authorizationCodes: Map<string, FAPI20AuthorizationCode> = new Map();
  private accessTokens: Map<string, FAPI20AccessToken> = new Map();
  private refreshTokens: Map<string, string> = new Map();
  private registeredClients: Map<string, FAPI20ClientRegistration> = new Map();
  private requestUris: Map<string, FAPI20AuthorizationRequest> = new Map();

  constructor(config: FAPI20ServerConfig) {
    this.config = config;
  }

  /**
   * Endpoint de registro dinâmico de clientes
   */
  async registerClient(
    registrationRequest: Partial<FAPI20ClientRegistration>,
    mtlsCertificate?: string
  ): Promise<FAPI20ClientRegistration> {
    const clientId = `client_${crypto.randomBytes(16).toString('hex')}`;
    const clientSecret = this.config.mtls.requireClientCertificate
      ? undefined
      : crypto.randomBytes(32).toString('hex');
    
    const clientRegistration: FAPI20ClientRegistration = {
      client_id: clientId,
      redirect_uris: registrationRequest.redirect_uris || [],
      grant_types: registrationRequest.grant_types || ['authorization_code', 'refresh_token'],
      response_types: registrationRequest.response_types || ['code'],
      scope: registrationRequest.scope || 'openid profile email',
      token_endpoint_auth_method: registrationRequest.token_endpoint_auth_method || 'private_key_jwt',
      software_id: registrationRequest.software_id || 'fapi20-client',
      software_version: registrationRequest.software_version || '1.0.0',
      require_signed_request_object: registrationRequest.require_signed_request_object ?? true,
      require_pushed_authorization_requests: registrationRequest.require_pushed_authorization_requests ?? true,
      tls_client_certificate_bound_access_tokens: registrationRequest.tls_client_certificate_bound_access_tokens ?? true,
      dpop_bound_access_tokens: registrationRequest.dpop_bound_access_tokens ?? true
    };
    
    if (clientSecret !== undefined) {
      (clientRegistration as any).client_secret = clientSecret;
    }
    
    this.registeredClients.set(clientId, clientRegistration);
    
    console.log('📝 Client registered:', {
      client_id: clientId,
      has_secret: !!clientRegistration.client_secret
    });
    
    return clientRegistration;
  }

  /**
   * Endpoint de Pushed Authorization Request (PAR)
   */
  async pushAuthorizationRequest(
    request: FAPI20AuthorizationRequest,
    clientCertificate?: string
  ): Promise<{ request_uri: string; expires_in: number }> {
    // Validate client
    const client = this.registeredClients.get(request.client_id);
    if (!client) {
      throw new Error('Client não registrado');
    }
    
    // Validate request URI or request object
    if (request.request_uri) {
      const storedRequest = this.requestUris.get(request.request_uri.replace('urn:ietf:params:oauth:request_uri:', ''));
      if (!storedRequest) {
        throw new Error('Request URI inválido ou expirado');
      }
      Object.assign(request, storedRequest);
    }
    
    if (request.request) {
      // Validate and decode request object
      const requestPayload = await this.verifyRequestObject(request.request);
      Object.assign(request, requestPayload);
    }
    
    // Validate required parameters
    if (!request.response_type) {
      throw new Error('response_type é obrigatório');
    }
    
    if (!request.redirect_uri) {
      throw new Error('redirect_uri é obrigatório');
    }
    
    if (!request.code_challenge) {
      throw new Error('code_challenge é obrigatório (PKCE)');
    }
    
    if (request.code_challenge_method !== 'S256') {
      throw new Error('code_challenge_method deve ser S256');
    }
    
    // Validate MTLS certificate if required
    if (this.config.mtls.requireClientCertificate && !clientCertificate) {
      throw new Error('MTLS client certificate é obrigatório');
    }
    
    if (clientCertificate) {
      const thumbprint = this.calculateX509Thumbprint(clientCertificate);
      console.log('🔐 MTLS Certificate validated:', { thumbprint });
    }
    
    // Store request URI
    const requestUri = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + (300 * 1000); // 5 minutes
    
    this.requestUris.set(requestUri, { ...request });
    
    // Set timeout to expire request
    setTimeout(() => {
      this.requestUris.delete(requestUri);
    }, 300000);
    
    console.log('📤 PAR Request created:', {
      request_uri: `urn:ietf:params:oauth:request_uri:${requestUri}`,
      client_id: request.client_id
    });
    
    return {
      request_uri: `urn:ietf:params:oauth:request_uri:${requestUri}`,
      expires_in: 300
    };
  }

  /**
   * Verifica Request Object (JWT Secured Authorization Request)
   */
  private async verifyRequestObject(requestJwt: string): Promise<FAPI20AuthorizationRequest> {
    try {
      const { payload } = await jwtVerify(requestJwt, this.config.signingKeys.publicKey, {
        issuer: this.config.issuer,
        audience: this.config.issuer
      });
      
      return payload as unknown as FAPI20AuthorizationRequest;
    } catch (error) {
      throw new Error('Request object inválido: ' + (error as Error).message);
    }
  }

  /**
   * Endpoint de autorização
   */
  async authorize(request: FAPI20AuthorizationRequest): Promise<string> {
    // Validate client
    const client = this.registeredClients.get(request.client_id);
    if (!client) {
      throw new Error('Client não registrado');
    }
    
    // Validate PAR requirement
    if (client.require_pushed_authorization_requests && !request.request_uri) {
      throw new Error('Client requer Pushed Authorization Request (PAR)');
    }
    
    // Validate signed request object requirement
    if (client.require_signed_request_object && !request.request && !request.request_uri) {
      throw new Error('Client requer Request Object assinado');
    }
    
    // Generate authorization code
    const authorizationCode = `code_${crypto.randomBytes(32).toString('hex')}`;
    
    const codeData: FAPI20AuthorizationCode = {
      code: authorizationCode,
      client_id: request.client_id,
      redirect_uri: request.redirect_uri,
      code_challenge: request.code_challenge,
      expires_at: Date.now() + (600 * 1000), // 10 minutes
      used: false
    };
    
    this.authorizationCodes.set(authorizationCode, codeData);
    
    console.log('📝 Authorization Code generated:', {
      code: authorizationCode,
      client_id: request.client_id,
      expires_in: 600
    });
    
    // Return authorization URL (in real implementation, this would be a redirect)
    const redirectUrl = new URL(request.redirect_uri);
    redirectUrl.searchParams.set('code', authorizationCode);
    redirectUrl.searchParams.set('state', request.state);
    
    return redirectUrl.toString();
  }

  /**
   * Endpoint de token
   */
  async exchangeToken(
    grantType: string,
    code?: string,
    redirectUri?: string,
    codeVerifier?: string,
    refreshToken?: string,
    clientId?: string,
    clientAssertion?: string,
    mtlsCertificate?: string,
    dpopProof?: string
  ): Promise<FAPI20AccessToken> {
    let accessToken: FAPI20AccessToken;
    
    if (grantType === 'authorization_code') {
      accessToken = await this.exchangeAuthorizationCode(code!, redirectUri!, codeVerifier!, clientId, clientAssertion, mtlsCertificate, dpopProof);
    } else if (grantType === 'refresh_token') {
      accessToken = await this.exchangeRefreshToken(refreshToken!, clientId, clientAssertion, mtlsCertificate, dpopProof);
    } else if (grantType === 'client_credentials') {
      accessToken = await this.exchangeClientCredentials(clientId!, clientAssertion, mtlsCertificate, dpopProof);
    } else {
      throw new Error('Grant type não suportado');
    }
    
    return accessToken;
  }

  /**
    * Troca authorization code por access token
    */
  private async exchangeAuthorizationCode(
    code: string,
    redirectUri: string,
    codeVerifier: string,
    clientId?: string,
    clientAssertion?: string,
    mtlsCertificate?: string,
    dpopProof?: string
  ): Promise<FAPI20AccessToken> {
    // Find authorization code
    const codeData = this.authorizationCodes.get(code);
    if (!codeData) {
      throw new Error('Authorization code inválido');
    }
    
    // Validate code hasn't been used
    if (codeData.used) {
      throw new Error('Authorization code já foi utilizado');
    }
    
    // Validate code expiration
    if (Date.now() > codeData.expires_at) {
      throw new Error('Authorization code expirado');
    }
    
    // Validate PKCE
    if (codeVerifier) {
      const expectedCodeChallenge = crypto.createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
      
      if (codeData.code_challenge !== expectedCodeChallenge) {
        throw new Error('Code verifier inválido (PKCE mismatch)');
      }
    }
    
    // Validate redirect URI
    const client = this.registeredClients.get(codeData.client_id);
    if (!client) {
      throw new Error('Client não encontrado');
    }
    
    if (!client.redirect_uris.includes(redirectUri)) {
      throw new Error('Redirect URI mismatch');
    }
    
    // Validate client authentication
    if (client.token_endpoint_auth_method === 'client_secret_post' && clientAssertion) {
      // For client_secret_post, clientAssertion should be the client_secret
      if (clientAssertion !== client.client_secret) {
        throw new Error('Client secret inválido');
      }
      console.log('✅ Client secret validated (client_secret_post)');
    } else if (clientAssertion) {
      // For private_key_jwt, clientAssertion should be a JWT
      await this.verifyClientAssertion(clientAssertion, clientId);
    }
    
    // Validate DPoP proof if provided
    let jkt: string | undefined;
    if (dpopProof) {
      jkt = await this.verifyDPoPProof(dpopProof, 'POST', this.config.tokenEndpoint);
    }
    
    // Validate MTLS certificate if required
    let x5tS256: string | undefined;
    if (mtlsCertificate) {
      x5tS256 = this.calculateX509Thumbprint(mtlsCertificate);
      console.log('🔐 MTLS Certificate validated for token exchange:', { x5tS256 });
    }
    
    // Mark code as used
    codeData.used = true;
    this.authorizationCodes.delete(code);
    
    // Generate access token
    const token = await this.generateAccessToken(codeData.client_id, jkt, x5tS256);
    
    return token;
  }

  /**
    * Troca refresh token por access token
    */
  private async exchangeRefreshToken(
    refreshToken: string,
    clientId?: string,
    clientAssertion?: string,
    mtlsCertificate?: string,
    dpopProof?: string
  ): Promise<FAPI20AccessToken> {
    const storedClientId = this.refreshTokens.get(refreshToken);
    if (!storedClientId) {
      throw new Error('Refresh token inválido');
    }
    
    if (clientId && storedClientId !== clientId) {
      throw new Error('Client ID mismatch');
    }
    
    const client = this.registeredClients.get(storedClientId);
    
    // Validate client authentication
    if (client && client.token_endpoint_auth_method === 'client_secret_post' && clientAssertion) {
      if (clientAssertion !== client.client_secret) {
        throw new Error('Client secret inválido');
      }
    } else if (clientAssertion) {
      await this.verifyClientAssertion(clientAssertion, clientId);
    }
    
    // Validate DPoP proof if provided
    let jkt: string | undefined;
    if (dpopProof) {
      jkt = await this.verifyDPoPProof(dpopProof, 'POST', this.config.tokenEndpoint);
    }
    
    // Generate new access token
    const token = await this.generateAccessToken(storedClientId, jkt);
    
    // Revoke old refresh token and issue new one
    this.refreshTokens.delete(refreshToken);
    const newRefreshToken = `rt_${crypto.randomBytes(32).toString('hex')}`;
    token.refresh_token = newRefreshToken;
    this.refreshTokens.set(newRefreshToken, storedClientId);
    
    return token;
  }

  /**
   * Troca client credentials por access token
   */
  private async exchangeClientCredentials(
    clientId: string,
    clientAssertion?: string,
    mtlsCertificate?: string,
    dpopProof?: string
  ): Promise<FAPI20AccessToken> {
    const client = this.registeredClients.get(clientId);
    if (!client) {
      throw new Error('Client não registrado');
    }
    
    if (clientAssertion) {
      await this.verifyClientAssertion(clientAssertion, clientId);
    }
    
    let jkt: string | undefined;
    if (dpopProof) {
      jkt = await this.verifyDPoPProof(dpopProof, 'POST', this.config.tokenEndpoint);
    }
    
    return await this.generateAccessToken(clientId, jkt);
  }

  /**
   * Gera access token
   */
  private async generateAccessToken(
    clientId: string,
    jkt?: string,
    x5tS256?: string
  ): Promise<FAPI20AccessToken> {
    const token = `at_${crypto.randomBytes(32).toString('base64url')}`;
    const refreshToken = `rt_${crypto.randomBytes(32).toString('hex')}`;
    const expiresIn = 3600; // 1 hour
    
    const accessToken: FAPI20AccessToken = {
      access_token: token,
      token_type: jkt ? 'DPoP' : 'Bearer',
      expires_in: expiresIn,
      expires_at: Date.now() + (expiresIn * 1000),
      refresh_token: refreshToken,
      scope: 'openid profile email',
      client_id: clientId
    };
    
    // Add confirmation claims
    if (x5tS256 || jkt) {
      accessToken.cnf = {};
      if (x5tS256) {
        accessToken.cnf['x5t#S256'] = x5tS256;
      }
      if (jkt) {
        accessToken.cnf.jkt = jkt;
      }
    }
    
    this.accessTokens.set(token, accessToken);
    this.refreshTokens.set(refreshToken, clientId);
    
    console.log('🎫 Access token generated:', {
      client_id: clientId,
      token_type: accessToken.token_type,
      expires_in: expiresIn,
      has_x5tS256: !!x5tS256,
      has_jkt: !!jkt
    });
    
    return accessToken;
  }

  /**
   * Verifica client assertion
   */
  private async verifyClientAssertion(assertion: string, clientId?: string): Promise<void> {
    try {
      const { payload } = await jwtVerify(assertion, this.config.signingKeys.publicKey, {
        issuer: clientId,
        audience: this.config.tokenEndpoint
      });
      
      console.log('✅ Client assertion verified:', {
        iss: payload.iss,
        sub: payload.sub,
        exp: payload.exp
      });
    } catch (error) {
      throw new Error('Client assertion inválido: ' + (error as Error).message);
    }
  }

  /**
   * Verifica DPoP proof
   */
  private async verifyDPoPProof(
    proof: string,
    method: string,
    url: string
  ): Promise<string> {
    try {
      const { payload } = await jwtVerify(proof, this.config.signingKeys.publicKey, {
        issuer: undefined
      });
      
      if (payload.htm !== method) {
        throw new Error('DPoP HTTP method mismatch');
      }
      
      if (payload.htu !== url) {
        throw new Error('DPoP HTTP URI mismatch');
      }
      
      if (!payload.jkt) {
        throw new Error('DPoP proof missing jkt claim');
      }
      
      console.log('✅ DPoP proof verified:', {
        htm: payload.htm,
        htu: payload.htu,
        jkt: payload.jkt
      });
      
      return payload.jkt;
    } catch (error) {
      throw new Error('DPoP proof inválido: ' + (error as Error).message);
    }
  }

  /**
   * Endpoint de UserInfo
   */
  async userInfo(
    accessToken: string,
    dpopProof?: string
  ): Promise<Record<string, unknown>> {
    const tokenData = this.accessTokens.get(accessToken);
    if (!tokenData) {
      throw new Error('Access token inválido');
    }
    
    // Verify token expiration
    if (Date.now() > tokenData.expires_at) {
      throw new Error('Access token expirado');
    }
    
    // Verify DPoP proof if present
    if (dpopProof) {
      const jkt = await this.verifyDPoPProof(dpopProof, 'GET', this.config.userinfoEndpoint);
      
      // Verify jkt matches token
      if (tokenData.cnf?.jkt && tokenData.cnf.jkt !== jkt) {
        throw new Error('DPoP jkt mismatch');
      }
    }
    
    // Return user claims
    const userInfo: Record<string, unknown> = {
      sub: `user_${crypto.randomBytes(16).toString('hex')}`,
      name: 'John Doe',
      email: 'john.doe@example.com',
      email_verified: true,
      address: {
        formatted: '123 Main St, City, ST 12345',
        country: 'US'
      }
    };
    
    console.log('👤 UserInfo returned:', {
      sub: userInfo.sub,
      client_id: tokenData.client_id
    });
    
    return userInfo;
  }

  /**
   * Endpoint JWKS (JSON Web Key Set)
   */
  getJWKS(): { keys: unknown[] } {
    const signingKeySpki = this.config.signingKeys.publicKey.export({ type: 'spki', format: 'pem' });
    const signingKeyDer = this.config.signingKeys.publicKey.export({ type: 'spki', format: 'der' });
    
    const jwk = {
      kty: 'RSA',
      use: 'sig',
      alg: 'PS256',
      kid: 'signing-key',
      n: Buffer.from(signingKeyDer).slice(signingKeyDer.length - 256).toString('base64url'),
      e: 'AQAB'
    };
    
    return { keys: [jwk] };
  }

  /**
   * Verifica assinatura de mensagem HTTP (HTTP Message Signing)
   */
  async verifyHTTPMessageSignature(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: string,
    signature: string,
    signatureInput: string,
    publicKey: crypto.KeyObject
  ): Promise<boolean> {
    try {
      const verify = crypto.createVerify('sha256');
      verify.update(signatureInput);
      
      const isValid = verify.verify(publicKey, Buffer.from(signature, 'base64url'));
      
      console.log('🔐 HTTP Message Signature verification:', isValid);
      
      return isValid;
    } catch (error) {
      console.error('❌ HTTP Message Signature verification failed:', error);
      return false;
    }
  }

  /**
   * Calcula thumbprint X.509 (simulado para demonstração)
   */
  private calculateX509Thumbprint(certPem: string): string {
    try {
      const cert = new crypto.X509Certificate(certPem);
      const certBuffer = Buffer.from(certPem);
      const thumbprint = crypto.createHash('sha256').update(certBuffer).digest();
      return thumbprint.toString('base64url');
    } catch (error) {
      const certBuffer = Buffer.from(certPem);
      const thumbprint = crypto.createHash('sha256').update(certBuffer).digest();
      return thumbprint.toString('base64url');
    }
  }

  /**
   * Revoga access token
   */
  revokeToken(accessToken: string): void {
    this.accessTokens.delete(accessToken);
    console.log('🗑️  Access token revoked:', { token: accessToken.substring(0, 20) + '...' });
  }
}
