import type { Tenant, CreateTenantInput, UpdateTenantInput, SigningKey, CreateSigningKeyInput } from '../../types/tenant.js';

/**
 * Storage interface for tenant management
 */
export interface ITenantStorage {
  /**
   * Create a new tenant
   */
  create(input: CreateTenantInput): Promise<Tenant>;

  /**
   * Find a tenant by ID
   */
  findById(id: string): Promise<Tenant | null>;

  /**
   * Find a tenant by slug
   */
  findBySlug(slug: string): Promise<Tenant | null>;

  /**
   * Update a tenant
   */
  update(id: string, input: UpdateTenantInput): Promise<Tenant>;

  /**
   * Delete a tenant
   */
  delete(id: string): Promise<void>;

  /**
   * List all tenants
   */
  list(options?: { limit?: number; offset?: number }): Promise<Tenant[]>;
}

/**
 * Storage interface for signing key management
 */
export interface ISigningKeyStorage {
  /**
   * Create a new signing key
   */
  create(input: CreateSigningKeyInput): Promise<SigningKey>;

  /**
   * Find a signing key by ID
   */
  findById(id: string): Promise<SigningKey | null>;

  /**
   * Find a signing key by key ID (kid)
   */
  findByKid(tenantId: string, kid: string): Promise<SigningKey | null>;

  /**
   * Get the primary signing key for a tenant
   */
  getPrimary(tenantId: string): Promise<SigningKey | null>;

  /**
   * List all signing keys for a tenant
   */
  listByTenant(tenantId: string): Promise<SigningKey[]>;

  /**
   * Set a key as primary (and unset others)
   */
  setPrimary(id: string): Promise<SigningKey>;

  /**
   * Delete a signing key
   */
  delete(id: string): Promise<void>;

  /**
   * Delete expired signing keys
   */
  deleteExpired(tenantId: string): Promise<number>;
}
