/**
 * Refresh Token (stored)
 */
export interface RefreshToken {
  id: string;
  tenantId: string;
  clientId: string;
  userId?: string;
  tokenHash: string;
  scope?: string;
  expiresAt: Date;
  issuedAt: Date;
  revokedAt?: Date;
  parentTokenId?: string;
  familyId: string;
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
  codeHash: string;
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
  issuedAt: Date;
  usedAt?: Date;
  sessionId?: string;
}

/**
 * Device Code (stored)
 */
export interface DeviceCode {
  id: string;
  tenantId: string;
  clientId: string;
  deviceCodeHash: string;
  userCode: string;
  scope?: string;
  expiresAt: Date;
  interval: number;
  issuedAt: Date;
  lastPolledAt?: Date;
  userId?: string;
  status: 'pending' | 'authorized' | 'denied' | 'expired';
}

/**
 * Revoked Token (for JWT revocation tracking)
 */
export interface RevokedToken {
  id: string;
  tenantId: string;
  tokenId: string;
  tokenType: 'access_token' | 'refresh_token';
  expiresAt: Date;
  revokedAt: Date;
}
