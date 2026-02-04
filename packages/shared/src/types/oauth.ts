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
