/**
 * FAPI 2.0 (Financial-grade API) - Index
 * 
 * Exportações principais do módulo FAPI 2.0
 * 
 * Implementação conforme:
 * - RFC 9420: FAPI 2.0 Security Profile
 * - OpenID Connect Core 1.0
 * - OpenID Connect FAPI 2.0 Security Profile
 * - RFC 9449: DPoP (Demonstrating Proof-of-Possession)
 * - RFC 7636: PKCE (Proof Key for Code Exchange)
 * - RFC 7519: JWT (JSON Web Token)
 * - RFC 7515: JWS (JSON Web Signature)
 * - RFC 7520: JARM (JWS Encrypted Response Mode)
 * 
 * @see https://openid.net/specs/openid-connect-fapi-2_0-1_0.html
 * @see https://www.rfc-editor.org/rfc/rfc9420.html
 */

// Client
export {
  FAPI20Client
} from './client';

export type {
  FAPI20ClientConfig,
  PARRequest,
  PARResponse,
  FAPITokenRequest,
  FAPITokenResponse,
  HTTPMessageSignature,
  FAPIRequestObject
} from './client';

// Server
export {
  FAPI20Server
} from './server';

export type {
  FAPI20ServerConfig,
  FAPI20ClientRegistration,
  FAPI20AuthorizationRequest,
  FAPI20AuthorizationCode,
  FAPI20AccessToken
} from './server';
