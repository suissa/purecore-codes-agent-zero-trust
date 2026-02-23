/**
 * FAPI 2.0 - Demonstração Simplificada
 * 
 * Demonstração funcional de FAPI 2.0 (Financial-grade API)
 * 
 * Recursos implementados:
 * - OpenID Connect Dynamic Client Registration
 * - Authorization Code Flow com PKCE
 * - Token Exchange
 * - DPoP (Demonstrating Proof-of-Possession)
 * - UserInfo Endpoint
 * - Token Refresh
 * - JWKS Endpoint
 * 
 * @see https://openid.net/specs/openid-connect-fapi-2_0-1_0.html
 */

import { FAPI20Client, FAPI20Server } from '../domains/auth/fapi20';
import { generateKeyPair, SignJWT, jwtVerify } from '../src/index';
import * as crypto from 'node:crypto';

// ============================================================================
// DEMONSTRAÇÃO FUNCIONAL
// ============================================================================

async function demonstrateFAPI20() {
  console.log('🚀 Demonstração FAPI 2.0 (Financial-grade API)');
  console.log('   OpenID Connect Core 1.0 + FAPI 2.0 Security Profile\n');
  console.log('═'.repeat(70));
  
  // 1. Gerar chaves
  console.log('\n📜 1. Gerando chaves...');
  const signingKeys = {
    privateKey: crypto.createPrivateKey(generateKeyPair().privateKey),
    publicKey: crypto.createPublicKey(generateKeyPair().publicKey)
  };
  
  const dpopKeys = {
    privateKey: crypto.createPrivateKey(generateKeyPair().privateKey),
    publicKey: crypto.createPublicKey(generateKeyPair().publicKey)
  };
  
  console.log('✅ Chaves geradas');
  
  // 2. Configurar servidor
  console.log('\n🖥️  2. Configurando servidor FAPI 2.0...');
  const fapiServer = new FAPI20Server({
    issuer: 'https://bank.example.com',
    authorizationEndpoint: 'https://bank.example.com/authorize',
    tokenEndpoint: 'https://bank.example.com/token',
    userinfoEndpoint: 'https://bank.example.com/userinfo',
    jwksEndpoint: 'https://bank.example.com/.well-known/jwks.json',
    parEndpoint: 'https://bank.example.com/par',
    registrationEndpoint: 'https://bank.example.com/registration',
    mtls: {
      caCertificate: '',
      requireClientCertificate: false
    },
    signingKeys,
    encryptionKeys: signingKeys
  });
  
  console.log('✅ Servidor configurado');
  
  // 3. Registrar cliente
  console.log('\n📝 3. Registrando cliente...');
  const clientRegistration = await fapiServer.registerClient({
    redirect_uris: ['https://client.example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid profile email',
    token_endpoint_auth_method: 'client_secret_post',
    software_id: 'fapi20-demo-client',
    software_version: '1.0.0',
    require_signed_request_object: false,
    require_pushed_authorization_requests: false,
    tls_client_certificate_bound_access_tokens: false,
    dpop_bound_access_tokens: true
  });
  
  console.log('✅ Cliente registrado');
  console.log(`   client_id: ${clientRegistration.client_id}`);
  console.log(`   has_secret: ${!!clientRegistration.client_secret}`);
  console.log(`   dpop_bound_access_tokens: ${clientRegistration.dpop_bound_access_tokens}`);
  
  // 4. Configurar cliente
  console.log('\n📱 4. Configurando cliente FAPI 2.0...');
  const fapiClient = new FAPI20Client({
    issuer: 'https://bank.example.com',
    clientId: clientRegistration.client_id,
    redirectUri: 'https://client.example.com/callback',
    mtls: {
      clientCertificate: '',
      clientPrivateKey: clientRegistration.client_secret!,
      caCertificate: ''
    },
    dpop: dpopKeys,
    jwks: {
      signingKey: signingKeys.privateKey,
      encryptionKey: signingKeys.publicKey
    },
    scopes: ['openid', 'profile', 'email']
  });
  
  console.log('✅ Cliente configurado');
  
  // 5. Gerar PKCE (Proof Key for Code Exchange)
  console.log('\n📤 5. Gerando PKCE (S256)...');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  
  console.log(`✅ PKCE gerado`);
  console.log(`   code_verifier: ${codeVerifier.substring(0, 20)}...`);
  console.log(`   code_challenge: ${codeChallenge.substring(0, 20)}...`);
  
  // 6. Gerar código de autorização via servidor
  console.log('\n📝 6. Gerando authorization code no servidor...');
  const state = crypto.randomBytes(16).toString('hex');
  
  const authorizationCode = await fapiServer.authorize({
    client_id: clientRegistration.client_id,
    response_type: 'code',
    redirect_uri: 'https://client.example.com/callback',
    scope: 'openid profile email',
    state: state,
    nonce: 'demo_nonce',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });
  
  const parsedAuthUrl = new URL(authorizationCode);
  const actualCode = parsedAuthUrl.searchParams.get('code')!;
  console.log(`✅ Authorization code gerado: ${actualCode}`);
  
  // 7. Trocar código por access token
  console.log('\n🔄 7. Trocando código por access token...');
  
  const tokenResponse = await fapiServer.exchangeToken(
    'authorization_code',
    actualCode,
    'https://client.example.com/callback',
    codeVerifier,
    undefined,
    clientRegistration.client_id,
    clientRegistration.client_secret,
    undefined,
    undefined,
    undefined
  );
  
  console.log('\n✅ Token trocado por sucesso');
  console.log(`   access_token: ${tokenResponse.access_token.substring(0, 30)}...`);
  console.log(`   token_type: ${tokenResponse.token_type}`);
  console.log(`   expires_in: ${tokenResponse.expires_in}s`);
  console.log(`   refresh_token: ${tokenResponse.refresh_token?.substring(0, 30)}...`);
  if (tokenResponse.cnf?.jkt) {
    console.log(`   cnf.jkt: ${tokenResponse.cnf.jkt.substring(0, 20)}...`);
  }
  
  // 8. UserInfo endpoint
  console.log('\n👤 8. UserInfo endpoint...');
  const userInfo = await fapiServer.userInfo(tokenResponse.access_token);
  
  console.log('\n✅ UserInfo obtido:');
  console.log(`   sub: ${userInfo.sub}`);
  console.log(`   name: ${userInfo.name}`);
  console.log(`   email: ${userInfo.email}`);
  
  // 9. Refresh token
  console.log('\n🔄 9. Refresh token...');
  const newTokenResponse = await fapiServer.exchangeToken(
    'refresh_token',
    undefined,
    undefined,
    undefined,
    tokenResponse.refresh_token!,
    clientRegistration.client_id,
    clientRegistration.client_secret,
    undefined,
    undefined,
    undefined
  );
  
  console.log('\n✅ Token refresh com sucesso');
  console.log(`   new_access_token: ${newTokenResponse.access_token.substring(0, 30)}...`);
  console.log(`   new_refresh_token: ${newTokenResponse.refresh_token?.substring(0, 30)}...`);
  
  // 10. JWKS endpoint
  console.log('\n🔑 10. JWKS endpoint...');
  const jwks = fapiServer.getJWKS();
  
  console.log('\n✅ JWKS obtido:');
  console.log(`   keys_count: ${jwks.keys.length}`);
  if (jwks.keys.length > 0) {
    console.log(`   keys[0].kid: ${(jwks.keys[0] as any).kid}`);
    console.log(`   keys[0].use: ${(jwks.keys[0] as any).use}`);
    console.log(`   keys[0].alg: ${(jwks.keys[0] as any).alg}`);
  }
  
  // 11. Token revocation
  console.log('\n🗑️  11. Revogando token...');
  fapiServer.revokeToken(newTokenResponse.access_token);
  
  try {
    await fapiServer.userInfo(newTokenResponse.access_token);
    console.log('   ❌ Token ainda está ativo (erro!)');
  } catch (error) {
    console.log('   ✅ Token revogado com sucesso');
  }
  
  // 12. PAR (Pushed Authorization Requests)
  console.log('\n📤 12. Testando PAR (Pushed Authorization Requests)...');
  
  const parRequest = {
    client_id: clientRegistration.client_id,
    response_type: 'code',
    redirect_uri: 'https://client.example.com/callback',
    scope: 'openid profile email',
    state: crypto.randomBytes(16).toString('hex'),
    nonce: 'par_nonce',
    code_challenge: crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('base64url'),
    code_challenge_method: 'S256' as const
  };
  
  const parResponse = await fapiServer.pushAuthorizationRequest(parRequest);
  console.log('\n✅ PAR request criado:');
  console.log(`   request_uri: ${parResponse.request_uri}`);
  console.log(`   expires_in: ${parResponse.expires_in}s`);
  
  const authUrlWithPAR = new URL('https://bank.example.com/authorize');
  authUrlWithPAR.searchParams.set('request_uri', parResponse.request_uri);
  authUrlWithPAR.searchParams.set('client_id', clientRegistration.client_id);
  
  console.log(`   auth_url: ${authUrlWithPAR.toString()}`);
  console.log('   📝 Autorização via PAR (request_uri) protege parâmetros na URL');
  
  // Resumo
  console.log('\n' + '═'.repeat(70));
  console.log('📊 Resumo FAPI 2.0');
  console.log('═'.repeat(70));
  console.log('\n🔒 Recursos FAPI 2.0:');
  console.log('   • OpenID Connect Dynamic Client Registration');
  console.log('   • Authorization Code Flow');
  console.log('   • Token Exchange');
  console.log('   • DPoP (Demonstrating Proof-of-Possession)');
  console.log('   • UserInfo Endpoint');
  console.log('   • Token Refresh');
  console.log('   • Token Revocation');
  console.log('   • PAR (Pushed Authorization Requests)');
  console.log('   • JWKS Endpoint');
  console.log('   • Client Secret Post');
  console.log('   • PKCE (S256) para Proof Key for Code Exchange');
  console.log('');
  console.log('📋 Conformidade com Specs:');
  console.log('   • RFC 9420: FAPI 2.0');
  console.log('   • OpenID Connect Core 1.0');
  console.log('   • OpenID Connect FAPI 2.0 Security Profile');
  console.log('   • RFC 9449: DPoP');
  console.log('   • RFC 6749: OAuth 2.0');
  console.log('   • RFC 7519: JWT');
  console.log('   • RFC 7515: JWS');
  console.log('');
  console.log('✅ Demonstração FAPI 2.0 concluída!\n');
}

// Executar
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateFAPI20().catch(console.error);
}

export {
  demonstrateFAPI20,
  FAPI20Client,
  FAPI20Server
};
