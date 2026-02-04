import type { OAuthClient, CreateClientInput, UpdateClientInput } from '../../types/client.js';

/**
 * Storage interface for OAuth client management
 */
export interface IClientStorage {
  /**
   * Create a new OAuth client
   * Returns the client with generated clientId and optionally clientSecret
   */
  create(input: CreateClientInput): Promise<{ client: OAuthClient; clientSecret?: string }>;

  /**
   * Find a client by internal ID
   */
  findById(id: string): Promise<OAuthClient | null>;

  /**
   * Find a client by client_id (public identifier)
   */
  findByClientId(tenantId: string, clientId: string): Promise<OAuthClient | null>;

  /**
   * Update a client
   */
  update(id: string, input: UpdateClientInput): Promise<OAuthClient>;

  /**
   * Regenerate client secret (for confidential clients)
   * Returns the new plaintext secret (only time it's available)
   */
  regenerateSecret(id: string): Promise<string>;

  /**
   * Delete a client
   */
  delete(id: string): Promise<void>;

  /**
   * List all clients for a tenant
   */
  listByTenant(
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<OAuthClient[]>;

  /**
   * Verify client credentials
   * Returns the client if credentials are valid, null otherwise
   */
  verifyCredentials(tenantId: string, clientId: string, clientSecret: string): Promise<OAuthClient | null>;
}
