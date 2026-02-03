import type { GrantType } from './oauth.js';

/**
 * Tenant configuration
 */
export interface Tenant {
  id: string;
  name: string;
  slug: string; // URL-safe identifier used in paths
  issuer: string; // Full issuer URL (e.g., https://auth.example.com/tenant-slug)
  allowedGrants: GrantType[];
  allowedScopes: string[];
  accessTokenTtl: number; // seconds
  refreshTokenTtl: number; // seconds
  authorizationCodeTtl: number; // seconds
  deviceCodeTtl: number; // seconds
  deviceCodeInterval: number; // seconds between polling
  requirePkce: boolean; // Always true per RFC 9700
  allowedRedirectUriPatterns?: string[]; // Optional allowlist for redirect URIs
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
  kid: string; // Key ID
  algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
  publicKey: string; // PEM format
  privateKey: string; // PEM format (encrypted at rest in production)
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
