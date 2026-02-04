import type { Tenant, SigningKey } from './tenant.js';
import type { OAuthClient } from './client.js';
import type { RefreshToken, AuthorizationCode, DeviceCode } from './token.js';
import type { IdentityProvider } from './identity-provider.js';

/**
 * Pagination parameters
 */
export interface PaginationParams {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Paginated response
 */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/**
 * Admin dashboard statistics
 */
export interface DashboardStats {
  tenantCount: number;
  clientCount: number;
  activeRefreshTokens: number;
  activeAuthorizationCodes: number;
  activeDeviceCodes: number;
  identityProviderCount: number;
}

/**
 * Tenant statistics
 */
export interface TenantStats {
  clientCount: number;
  activeRefreshTokens: number;
  activeAuthorizationCodes: number;
  activeDeviceCodes: number;
  signingKeyCount: number;
  identityProviderCount: number;
}

/**
 * Token filter parameters
 */
export interface TokenFilterParams extends PaginationParams {
  userId?: string;
  clientId?: string;
  active?: boolean;
}

/**
 * Bulk revocation result
 */
export interface BulkRevocationResult {
  revokedCount: number;
}

/**
 * Client with plaintext secret (only on creation)
 */
export interface ClientWithSecret extends OAuthClient {
  clientSecret?: string;
}

/**
 * Key rotation result
 */
export interface KeyRotationResult {
  newKey: SigningKey;
  previousPrimaryKey?: SigningKey;
}

/**
 * Admin API types - re-export for convenience
 */
export type {
  Tenant,
  SigningKey,
  OAuthClient,
  RefreshToken,
  AuthorizationCode,
  DeviceCode,
  IdentityProvider,
};
