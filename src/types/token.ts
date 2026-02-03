import type { AddressClaim } from './user.js';

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
 * OpenID Connect Core 1.0 Section 2
 */
export interface IdTokenPayload {
  // Required claims
  iss: string; // Issuer
  sub: string; // Subject (user ID)
  aud: string | string[]; // Audience (client_id)
  exp: number; // Expiration time
  iat: number; // Issued at

  // Authentication claims
  auth_time?: number; // Time of authentication
  nonce?: string; // Nonce from authorization request
  acr?: string; // Authentication Context Class Reference
  amr?: string[]; // Authentication Methods References
  azp?: string; // Authorized party (client_id when multiple audiences)

  // Profile scope claims
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  updated_at?: number;

  // Email scope claims
  email?: string;
  email_verified?: boolean;

  // Address scope claims
  address?: AddressClaim;

  // Phone scope claims
  phone_number?: string;
  phone_number_verified?: boolean;

  // Session claims (for logout)
  sid?: string; // Session ID
}

/**
 * UserInfo Response
 * OpenID Connect Core 1.0 Section 5.3.2
 */
export interface UserInfoResponse {
  sub: string;

  // Profile scope
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  updated_at?: number;

  // Email scope
  email?: string;
  email_verified?: boolean;

  // Address scope
  address?: AddressClaim;

  // Phone scope
  phone_number?: string;
  phone_number_verified?: boolean;
}

/**
 * Logout Token for back-channel logout
 * OpenID Connect Back-Channel Logout 1.0
 */
export interface LogoutTokenPayload {
  iss: string;
  sub?: string;
  aud: string | string[];
  iat: number;
  jti: string;
  events: {
    'http://schemas.openid.net/event/backchannel-logout': Record<string, never>;
  };
  sid?: string;
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
  sessionId?: string; // Session association for logout
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
  sessionId?: string;
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
  responseMode?: 'query' | 'fragment' | 'form_post';
  claims?: string; // JSON-encoded claims parameter
  acr?: string; // Requested ACR
  expiresAt: Date;
  issuedAt: Date;
  usedAt?: Date; // Single use tracking
  sessionId?: string;
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
  responseMode?: 'query' | 'fragment' | 'form_post';
  claims?: string;
  acr?: string;
  expiresAt: Date;
  sessionId?: string;
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

/**
 * Claims request parameter
 * OpenID Connect Core 1.0 Section 5.5
 */
export interface ClaimsRequest {
  userinfo?: Record<string, ClaimConfig | null>;
  id_token?: Record<string, ClaimConfig | null>;
}

/**
 * Individual claim configuration
 */
export interface ClaimConfig {
  essential?: boolean;
  value?: string;
  values?: string[];
}
