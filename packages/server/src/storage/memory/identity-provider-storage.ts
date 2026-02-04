import type {
  IdentityProvider,
  CreateIdentityProviderInput,
  UpdateIdentityProviderInput,
  IIdentityProviderStorage,
} from '../interfaces/identity-provider-storage.js';
import { generateId } from '../../crypto/index.js';
import { encrypt } from '../../crypto/encrypt.js';

/**
 * In-memory identity provider storage implementation
 */
export class MemoryIdentityProviderStorage implements IIdentityProviderStorage {
  private providers = new Map<string, IdentityProvider>();
  private slugIndex = new Map<string, string>(); // `${tenantId}:${slug}` -> id

  async create(input: CreateIdentityProviderInput): Promise<IdentityProvider> {
    const id = generateId();
    const now = new Date();

    // Encrypt the client secret
    const clientSecretEncrypted = encrypt(input.clientSecret);

    const provider: IdentityProvider = {
      id,
      tenantId: input.tenantId,
      name: input.name,
      slug: input.slug,
      type: input.type ?? 'oidc',
      template: input.template,
      clientId: input.clientId,
      clientSecretEncrypted,
      issuer: input.issuer,
      authorizationEndpoint: input.authorizationEndpoint,
      tokenEndpoint: input.tokenEndpoint,
      userinfoEndpoint: input.userinfoEndpoint,
      jwksUri: input.jwksUri,
      scopes: input.scopes ?? ['openid', 'profile', 'email'],
      attributeMapping: input.attributeMapping,
      enabled: input.enabled ?? true,
      displayOrder: input.displayOrder,
      iconUrl: input.iconUrl,
      buttonText: input.buttonText,
      metadata: input.metadata,
      createdAt: now,
      updatedAt: now,
    };

    this.providers.set(id, provider);
    this.slugIndex.set(`${input.tenantId}:${input.slug}`, id);

    return provider;
  }

  async findById(id: string): Promise<IdentityProvider | null> {
    return this.providers.get(id) ?? null;
  }

  async findBySlug(tenantId: string, slug: string): Promise<IdentityProvider | null> {
    const id = this.slugIndex.get(`${tenantId}:${slug}`);
    if (!id) return null;
    return this.providers.get(id) ?? null;
  }

  async update(id: string, input: UpdateIdentityProviderInput): Promise<IdentityProvider> {
    const provider = this.providers.get(id);
    if (!provider) {
      throw new Error(`Identity provider not found: ${id}`);
    }

    // If client secret is being updated, encrypt it
    let clientSecretEncrypted = provider.clientSecretEncrypted;
    if (input.clientSecret) {
      clientSecretEncrypted = encrypt(input.clientSecret);
    }

    const updated: IdentityProvider = {
      ...provider,
      name: input.name ?? provider.name,
      clientId: input.clientId ?? provider.clientId,
      clientSecretEncrypted,
      issuer: input.issuer ?? provider.issuer,
      authorizationEndpoint: input.authorizationEndpoint ?? provider.authorizationEndpoint,
      tokenEndpoint: input.tokenEndpoint ?? provider.tokenEndpoint,
      userinfoEndpoint: input.userinfoEndpoint ?? provider.userinfoEndpoint,
      jwksUri: input.jwksUri ?? provider.jwksUri,
      scopes: input.scopes ?? provider.scopes,
      attributeMapping: input.attributeMapping ?? provider.attributeMapping,
      enabled: input.enabled ?? provider.enabled,
      displayOrder: input.displayOrder ?? provider.displayOrder,
      iconUrl: input.iconUrl ?? provider.iconUrl,
      buttonText: input.buttonText ?? provider.buttonText,
      metadata: input.metadata ?? provider.metadata,
      updatedAt: new Date(),
    };

    this.providers.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<void> {
    const provider = this.providers.get(id);
    if (provider) {
      this.slugIndex.delete(`${provider.tenantId}:${provider.slug}`);
      this.providers.delete(id);
    }
  }

  async listByTenant(tenantId: string): Promise<IdentityProvider[]> {
    return Array.from(this.providers.values())
      .filter((p) => p.tenantId === tenantId)
      .sort((a, b) => (a.displayOrder ?? 999) - (b.displayOrder ?? 999));
  }

  async listEnabledByTenant(tenantId: string): Promise<IdentityProvider[]> {
    return Array.from(this.providers.values())
      .filter((p) => p.tenantId === tenantId && p.enabled)
      .sort((a, b) => (a.displayOrder ?? 999) - (b.displayOrder ?? 999));
  }
}
