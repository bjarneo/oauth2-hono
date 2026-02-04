import type { GrantType } from './oauth.js';

/**
 * Tenant configuration
 */
export interface Tenant {
  id: string;
  name: string;
  slug: string;
  issuer: string;
  allowedGrants: GrantType[];
  allowedScopes: string[];
  accessTokenTtl: number;
  refreshTokenTtl: number;
  authorizationCodeTtl: number;
  deviceCodeTtl: number;
  deviceCodeInterval: number;
  requirePkce: boolean;
  allowedRedirectUriPatterns?: string[];
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Tenant creation input
 */
export interface CreateTenantInput {
  name: string;
  slug: string;
  issuer?: string;
  allowedGrants?: GrantType[];
  allowedScopes?: string[];
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  authorizationCodeTtl?: number;
  deviceCodeTtl?: number;
  deviceCodeInterval?: number;
  allowedRedirectUriPatterns?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Tenant update input
 */
export interface UpdateTenantInput {
  name?: string;
  issuer?: string;
  allowedGrants?: GrantType[];
  allowedScopes?: string[];
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  authorizationCodeTtl?: number;
  deviceCodeTtl?: number;
  deviceCodeInterval?: number;
  allowedRedirectUriPatterns?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Signing key for a tenant
 */
export interface SigningKey {
  id: string;
  tenantId: string;
  kid: string;
  algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
  publicKey: string;
  privateKey: string;
  isPrimary: boolean;
  expiresAt?: Date;
  createdAt: Date;
}

/**
 * Signing key creation input
 */
export interface CreateSigningKeyInput {
  tenantId: string;
  algorithm?: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
  isPrimary?: boolean;
  expiresAt?: Date;
}
