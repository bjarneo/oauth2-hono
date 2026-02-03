import type { RefreshToken, CreateRefreshTokenInput, RevokedToken } from '../../types/token.js';

/**
 * Storage interface for refresh token management
 */
export interface IRefreshTokenStorage {
  /**
   * Create a new refresh token
   * Returns the token record and the plaintext token value
   */
  create(input: CreateRefreshTokenInput): Promise<{ token: RefreshToken; value: string }>;

  /**
   * Find a refresh token by its hash
   */
  findByHash(tenantId: string, tokenHash: string): Promise<RefreshToken | null>;

  /**
   * Find a refresh token by plaintext value
   */
  findByValue(tenantId: string, tokenValue: string): Promise<RefreshToken | null>;

  /**
   * Revoke a refresh token by ID
   */
  revoke(id: string): Promise<void>;

  /**
   * Revoke all tokens in a family (for replay detection)
   */
  revokeFamily(tenantId: string, familyId: string): Promise<number>;

  /**
   * Revoke all tokens for a user-client pair
   */
  revokeByUserAndClient(tenantId: string, userId: string, clientId: string): Promise<number>;

  /**
   * Revoke all tokens for a user
   */
  revokeByUser(tenantId: string, userId: string): Promise<number>;

  /**
   * Check if a token has been revoked
   */
  isRevoked(id: string): Promise<boolean>;

  /**
   * Delete expired tokens (cleanup)
   */
  deleteExpired(tenantId: string): Promise<number>;
}

/**
 * Storage interface for JWT revocation tracking
 * Used for access tokens since they're stateless JWTs
 */
export interface IRevokedTokenStorage {
  /**
   * Mark a JWT as revoked
   */
  revoke(
    tenantId: string,
    tokenId: string, // jti claim
    tokenType: 'access_token' | 'refresh_token',
    expiresAt: Date
  ): Promise<RevokedToken>;

  /**
   * Check if a JWT has been revoked
   */
  isRevoked(tenantId: string, tokenId: string): Promise<boolean>;

  /**
   * Delete expired revocation records (cleanup)
   */
  deleteExpired(tenantId: string): Promise<number>;
}
