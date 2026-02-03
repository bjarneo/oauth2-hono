/**
 * OAuth 2.0 Grant Types
 * RFC 6749, RFC 8628
 */
export type GrantType =
  | 'authorization_code'
  | 'client_credentials'
  | 'refresh_token'
  | 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Response types for authorization endpoint
 */
export type ResponseType = 'code';

/**
 * PKCE Code Challenge Methods
 * RFC 9700 requires S256 only
 */
export type CodeChallengeMethod = 'S256';

/**
 * Token types
 */
export type TokenType = 'Bearer';

/**
 * Authorization Request (GET /authorize)
 * RFC 6749 Section 4.1.1
 */
export interface AuthorizationRequest {
  response_type: ResponseType;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  nonce?: string;
}

/**
 * Authorization Response
 * RFC 6749 Section 4.1.2
 */
export interface AuthorizationResponse {
  code: string;
  state?: string;
  iss: string; // RFC 9700 requires issuer in response
}

/**
 * Token Request Base
 */
export interface TokenRequestBase {
  grant_type: GrantType;
  client_id?: string;
  client_secret?: string;
}

/**
 * Authorization Code Token Request
 * RFC 6749 Section 4.1.3
 */
export interface AuthorizationCodeTokenRequest extends TokenRequestBase {
  grant_type: 'authorization_code';
  code: string;
  redirect_uri: string;
  code_verifier: string;
}

/**
 * Client Credentials Token Request
 * RFC 6749 Section 4.4.2
 */
export interface ClientCredentialsTokenRequest extends TokenRequestBase {
  grant_type: 'client_credentials';
  scope?: string;
}

/**
 * Refresh Token Request
 * RFC 6749 Section 6
 */
export interface RefreshTokenRequest extends TokenRequestBase {
  grant_type: 'refresh_token';
  refresh_token: string;
  scope?: string;
}

/**
 * Device Code Token Request
 * RFC 8628 Section 3.4
 */
export interface DeviceCodeTokenRequest extends TokenRequestBase {
  grant_type: 'urn:ietf:params:oauth:grant-type:device_code';
  device_code: string;
}

export type TokenRequest =
  | AuthorizationCodeTokenRequest
  | ClientCredentialsTokenRequest
  | RefreshTokenRequest
  | DeviceCodeTokenRequest;

/**
 * Token Response
 * RFC 6749 Section 5.1
 */
export interface TokenResponse {
  access_token: string;
  token_type: TokenType;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

/**
 * Device Authorization Request
 * RFC 8628 Section 3.1
 */
export interface DeviceAuthorizationRequest {
  client_id: string;
  scope?: string;
}

/**
 * Device Authorization Response
 * RFC 8628 Section 3.2
 */
export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

/**
 * Token Revocation Request
 * RFC 7009 Section 2.1
 */
export interface RevocationRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
  client_id?: string;
  client_secret?: string;
}

/**
 * Token Introspection Request
 * RFC 7662 Section 2.1
 */
export interface IntrospectionRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
  client_id?: string;
  client_secret?: string;
}

/**
 * Token Introspection Response
 * RFC 7662 Section 2.2
 */
export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: TokenType;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string | string[];
  iss?: string;
  jti?: string;
}

/**
 * OpenID Connect Discovery Response
 * Based on OpenID Connect Discovery 1.0
 */
export interface OpenIDConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  introspection_endpoint: string;
  device_authorization_endpoint: string;
  jwks_uri: string;
  response_types_supported: ResponseType[];
  grant_types_supported: GrantType[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: CodeChallengeMethod[];
  scopes_supported?: string[];
  claims_supported?: string[];
}

/**
 * JWKS Response
 */
export interface JWKSResponse {
  keys: JsonWebKey[];
}

export interface JsonWebKey {
  kty: string;
  use?: string;
  key_ops?: string[];
  alg?: string;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  // RSA specific
  n?: string;
  e?: string;
  // EC specific
  crv?: string;
  x?: string;
  y?: string;
}
