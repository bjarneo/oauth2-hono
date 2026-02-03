import type { Tenant, CreateTenantInput, UpdateTenantInput, SigningKey, CreateSigningKeyInput } from '../../types/tenant.js';
import type { ITenantStorage, ISigningKeyStorage } from '../interfaces/tenant-storage.js';
import { generateId, generateKid, generateRsaKeyPair, generateEcKeyPair } from '../../crypto/index.js';
import { getConfig } from '../../config/index.js';
import {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  GRANT_TYPE_DEVICE_CODE,
} from '../../config/constants.js';

/**
 * In-memory tenant storage implementation
 */
export class MemoryTenantStorage implements ITenantStorage {
  private tenants = new Map<string, Tenant>();
  private slugIndex = new Map<string, string>(); // slug -> id

  async create(input: CreateTenantInput): Promise<Tenant> {
    const config = getConfig();
    const id = generateId();
    const now = new Date();

    const tenant: Tenant = {
      id,
      name: input.name,
      slug: input.slug,
      issuer: input.issuer ?? `http://localhost:${config.server.port}/${input.slug}`,
      allowedGrants: input.allowedGrants ?? [
        GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_CLIENT_CREDENTIALS,
        GRANT_TYPE_REFRESH_TOKEN,
        GRANT_TYPE_DEVICE_CODE,
      ],
      allowedScopes: input.allowedScopes ?? ['openid', 'profile', 'email', 'offline_access'],
      accessTokenTtl: input.accessTokenTtl ?? config.defaults.accessTokenTtl,
      refreshTokenTtl: input.refreshTokenTtl ?? config.defaults.refreshTokenTtl,
      authorizationCodeTtl: input.authorizationCodeTtl ?? config.defaults.authorizationCodeTtl,
      deviceCodeTtl: input.deviceCodeTtl ?? config.defaults.deviceCodeTtl,
      deviceCodeInterval: input.deviceCodeInterval ?? config.defaults.deviceCodeInterval,
      requirePkce: true, // Always true per RFC 9700
      allowedRedirectUriPatterns: input.allowedRedirectUriPatterns,
      metadata: input.metadata,
      createdAt: now,
      updatedAt: now,
    };

    this.tenants.set(id, tenant);
    this.slugIndex.set(input.slug, id);

    return tenant;
  }

  async findById(id: string): Promise<Tenant | null> {
    return this.tenants.get(id) ?? null;
  }

  async findBySlug(slug: string): Promise<Tenant | null> {
    const id = this.slugIndex.get(slug);
    if (!id) return null;
    return this.tenants.get(id) ?? null;
  }

  async update(id: string, input: UpdateTenantInput): Promise<Tenant> {
    const tenant = this.tenants.get(id);
    if (!tenant) {
      throw new Error(`Tenant not found: ${id}`);
    }

    const updated: Tenant = {
      ...tenant,
      ...input,
      updatedAt: new Date(),
    };

    this.tenants.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<void> {
    const tenant = this.tenants.get(id);
    if (tenant) {
      this.slugIndex.delete(tenant.slug);
      this.tenants.delete(id);
    }
  }

  async list(options?: { limit?: number; offset?: number }): Promise<Tenant[]> {
    const all = Array.from(this.tenants.values());
    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? all.length;
    return all.slice(offset, offset + limit);
  }
}

/**
 * In-memory signing key storage implementation
 */
export class MemorySigningKeyStorage implements ISigningKeyStorage {
  private keys = new Map<string, SigningKey>();
  private tenantKeys = new Map<string, Set<string>>(); // tenantId -> Set<keyId>

  async create(input: CreateSigningKeyInput): Promise<SigningKey> {
    const id = generateId();
    const kid = generateKid();
    const algorithm = input.algorithm ?? 'RS256';

    // Generate key pair based on algorithm
    let keyPair: { publicKey: string; privateKey: string };
    if (algorithm.startsWith('RS')) {
      keyPair = await generateRsaKeyPair(algorithm as 'RS256' | 'RS384' | 'RS512');
    } else {
      keyPair = await generateEcKeyPair(algorithm as 'ES256' | 'ES384' | 'ES512');
    }

    const signingKey: SigningKey = {
      id,
      tenantId: input.tenantId,
      kid,
      algorithm,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      isPrimary: input.isPrimary ?? false,
      expiresAt: input.expiresAt,
      createdAt: new Date(),
    };

    // If this is the primary key, unset other primary keys
    if (signingKey.isPrimary) {
      const tenantKeyIds = this.tenantKeys.get(input.tenantId);
      if (tenantKeyIds) {
        for (const keyId of tenantKeyIds) {
          const key = this.keys.get(keyId);
          if (key && key.isPrimary) {
            this.keys.set(keyId, { ...key, isPrimary: false });
          }
        }
      }
    }

    this.keys.set(id, signingKey);

    // Update tenant index
    if (!this.tenantKeys.has(input.tenantId)) {
      this.tenantKeys.set(input.tenantId, new Set());
    }
    this.tenantKeys.get(input.tenantId)!.add(id);

    return signingKey;
  }

  async findById(id: string): Promise<SigningKey | null> {
    return this.keys.get(id) ?? null;
  }

  async findByKid(tenantId: string, kid: string): Promise<SigningKey | null> {
    const tenantKeyIds = this.tenantKeys.get(tenantId);
    if (!tenantKeyIds) return null;

    for (const keyId of tenantKeyIds) {
      const key = this.keys.get(keyId);
      if (key && key.kid === kid) {
        return key;
      }
    }
    return null;
  }

  async getPrimary(tenantId: string): Promise<SigningKey | null> {
    const tenantKeyIds = this.tenantKeys.get(tenantId);
    if (!tenantKeyIds) return null;

    for (const keyId of tenantKeyIds) {
      const key = this.keys.get(keyId);
      if (key && key.isPrimary) {
        return key;
      }
    }
    return null;
  }

  async listByTenant(tenantId: string): Promise<SigningKey[]> {
    const tenantKeyIds = this.tenantKeys.get(tenantId);
    if (!tenantKeyIds) return [];

    const keys: SigningKey[] = [];
    for (const keyId of tenantKeyIds) {
      const key = this.keys.get(keyId);
      if (key) {
        keys.push(key);
      }
    }
    return keys;
  }

  async setPrimary(id: string): Promise<SigningKey> {
    const key = this.keys.get(id);
    if (!key) {
      throw new Error(`Signing key not found: ${id}`);
    }

    // Unset other primary keys for this tenant
    const tenantKeyIds = this.tenantKeys.get(key.tenantId);
    if (tenantKeyIds) {
      for (const keyId of tenantKeyIds) {
        const k = this.keys.get(keyId);
        if (k && k.isPrimary && k.id !== id) {
          this.keys.set(keyId, { ...k, isPrimary: false });
        }
      }
    }

    const updated = { ...key, isPrimary: true };
    this.keys.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<void> {
    const key = this.keys.get(id);
    if (key) {
      const tenantKeyIds = this.tenantKeys.get(key.tenantId);
      tenantKeyIds?.delete(id);
      this.keys.delete(id);
    }
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const tenantKeyIds = this.tenantKeys.get(tenantId);
    if (!tenantKeyIds) return 0;

    const now = new Date();
    let deleted = 0;

    for (const keyId of Array.from(tenantKeyIds)) {
      const key = this.keys.get(keyId);
      if (key && key.expiresAt && key.expiresAt < now) {
        tenantKeyIds.delete(keyId);
        this.keys.delete(keyId);
        deleted++;
      }
    }

    return deleted;
  }
}
