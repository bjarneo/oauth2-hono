/**
 * JWT Access Token Payload
 * Standard claims from RFC 7519 + OAuth 2.0 claims
 */
export interface AccessTokenPayload {
  // Standard JWT claims
  iss: string; // Issuer
  sub: string; // Subject (user ID or client ID)
  aud: string | string[]; // Audience
  exp: number; // Expiration time
  iat: number; // Issued at
  nbf?: number; // Not before
  jti: string; // JWT ID (unique identifier)

  // OAuth 2.0 claims
  client_id: string;
  scope?: string;
  token_type: 'access_token';

  // Custom claims
  tenant_id: string;

  // Allow additional claims
  [key: string]: unknown;
}

/**
 * ID Token Payload (OpenID Connect)
 */
export interface IdTokenPayload {
  // Standard JWT claims
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;

  // OpenID Connect claims
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string[];
  azp?: string;

  // User claims (depending on scopes)
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
}

/**
 * Refresh Token (stored)
 */
export interface RefreshToken {
  id: string;
  tenantId: string;
  clientId: string;
  userId?: string; // Optional for client_credentials
  tokenHash: string; // Hashed token value
  scope?: string;
  expiresAt: Date;
  issuedAt: Date;
  revokedAt?: Date;
  parentTokenId?: string; // For rotation tracking
  familyId: string; // Token family for replay detection
  metadata?: Record<string, unknown>;
}

/**
 * Refresh token creation input
 */
export interface CreateRefreshTokenInput {
  tenantId: string;
  clientId: string;
  userId?: string;
  scope?: string;
  expiresAt: Date;
  parentTokenId?: string;
  familyId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Authorization Code (stored)
 */
export interface AuthorizationCode {
  id: string;
  tenantId: string;
  clientId: string;
  userId: string;
  codeHash: string; // Hashed code value
  redirectUri: string;
  scope?: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
  state?: string;
  expiresAt: Date;
  issuedAt: Date;
  usedAt?: Date; // Single use tracking
}

/**
 * Authorization code creation input
 */
export interface CreateAuthorizationCodeInput {
  tenantId: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope?: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
  state?: string;
  expiresAt: Date;
}

/**
 * Device Code (stored)
 * RFC 8628
 */
export interface DeviceCode {
  id: string;
  tenantId: string;
  clientId: string;
  deviceCodeHash: string;
  userCode: string; // User-facing code
  scope?: string;
  expiresAt: Date;
  interval: number; // Polling interval in seconds
  issuedAt: Date;
  lastPolledAt?: Date;
  userId?: string; // Set when user authorizes
  status: 'pending' | 'authorized' | 'denied' | 'expired';
}

/**
 * Device code creation input
 */
export interface CreateDeviceCodeInput {
  tenantId: string;
  clientId: string;
  scope?: string;
  expiresAt: Date;
  interval: number;
}

/**
 * Revoked Token (for JWT revocation tracking)
 */
export interface RevokedToken {
  id: string;
  tenantId: string;
  tokenId: string; // jti claim from JWT
  tokenType: 'access_token' | 'refresh_token';
  expiresAt: Date; // When the original token would have expired
  revokedAt: Date;
}
