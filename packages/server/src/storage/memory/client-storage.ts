import type { OAuthClient, CreateClientInput, UpdateClientInput } from '../../types/client.js';
import type { IClientStorage } from '../interfaces/client-storage.js';
import {
  generateId,
  generateClientId,
  generateClientSecret,
  hashClientSecret,
  verifyClientSecret,
} from '../../crypto/index.js';

/**
 * In-memory OAuth client storage implementation
 */
export class MemoryClientStorage implements IClientStorage {
  private clients = new Map<string, OAuthClient>();
  private clientIdIndex = new Map<string, string>(); // `${tenantId}:${clientId}` -> id

  async create(input: CreateClientInput): Promise<{ client: OAuthClient; clientSecret?: string }> {
    const id = generateId();
    const clientId = generateClientId();
    const now = new Date();

    let clientSecretHash: string | undefined;
    let clientSecret: string | undefined;

    // Generate secret for confidential clients
    if (input.clientType === 'confidential' && input.authMethod !== 'private_key_jwt') {
      clientSecret = generateClientSecret();
      clientSecretHash = await hashClientSecret(clientSecret);
    }

    const client: OAuthClient = {
      id,
      tenantId: input.tenantId,
      clientId,
      clientSecretHash,
      clientType: input.clientType,
      authMethod: input.authMethod,
      name: input.name,
      description: input.description,
      redirectUris: input.redirectUris,
      allowedGrants: input.allowedGrants,
      allowedScopes: input.allowedScopes,
      defaultScopes: input.defaultScopes,
      jwksUri: input.jwksUri,
      jwks: input.jwks,
      accessTokenTtl: input.accessTokenTtl,
      refreshTokenTtl: input.refreshTokenTtl,
      requireConsent: input.requireConsent ?? true,
      firstParty: input.firstParty ?? false,
      metadata: input.metadata,
      createdAt: now,
      updatedAt: now,
    };

    this.clients.set(id, client);
    this.clientIdIndex.set(`${input.tenantId}:${clientId}`, id);

    return { client, clientSecret };
  }

  async findById(id: string): Promise<OAuthClient | null> {
    return this.clients.get(id) ?? null;
  }

  async findByClientId(tenantId: string, clientId: string): Promise<OAuthClient | null> {
    const id = this.clientIdIndex.get(`${tenantId}:${clientId}`);
    if (!id) return null;
    return this.clients.get(id) ?? null;
  }

  async update(id: string, input: UpdateClientInput): Promise<OAuthClient> {
    const client = this.clients.get(id);
    if (!client) {
      throw new Error(`Client not found: ${id}`);
    }

    const updated: OAuthClient = {
      ...client,
      ...input,
      updatedAt: new Date(),
    };

    this.clients.set(id, updated);
    return updated;
  }

  async regenerateSecret(id: string): Promise<string> {
    const client = this.clients.get(id);
    if (!client) {
      throw new Error(`Client not found: ${id}`);
    }

    if (client.clientType !== 'confidential') {
      throw new Error('Cannot generate secret for public client');
    }

    const newSecret = generateClientSecret();
    const newHash = await hashClientSecret(newSecret);

    const updated: OAuthClient = {
      ...client,
      clientSecretHash: newHash,
      updatedAt: new Date(),
    };

    this.clients.set(id, updated);
    return newSecret;
  }

  async delete(id: string): Promise<void> {
    const client = this.clients.get(id);
    if (client) {
      this.clientIdIndex.delete(`${client.tenantId}:${client.clientId}`);
      this.clients.delete(id);
    }
  }

  async listByTenant(
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<OAuthClient[]> {
    const clients = Array.from(this.clients.values()).filter(
      (client) => client.tenantId === tenantId
    );
    const offset = options?.offset ?? 0;
    const limit = options?.limit ?? clients.length;
    return clients.slice(offset, offset + limit);
  }

  async verifyCredentials(
    tenantId: string,
    clientId: string,
    clientSecret: string
  ): Promise<OAuthClient | null> {
    const client = await this.findByClientId(tenantId, clientId);
    if (!client) return null;

    if (!client.clientSecretHash) {
      // Public client or private_key_jwt - no secret to verify
      return null;
    }

    const isValid = await verifyClientSecret(clientSecret, client.clientSecretHash);
    return isValid ? client : null;
  }
}
