/**
 * Federated identity - links external provider identities to local users
 */
export interface FederatedIdentity {
  id: string;
  tenantId: string;
  userId: string;
  providerId: string;
  providerUserId: string;
  providerUserData?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Input for creating a federated identity
 */
export interface CreateFederatedIdentityInput {
  tenantId: string;
  userId: string;
  providerId: string;
  providerUserId: string;
  providerUserData?: Record<string, unknown>;
}

/**
 * Input for updating a federated identity
 */
export interface UpdateFederatedIdentityInput {
  providerUserData?: Record<string, unknown>;
}

/**
 * Storage interface for federated identity management
 */
export interface IFederatedIdentityStorage {
  /**
   * Create a new federated identity link
   */
  create(input: CreateFederatedIdentityInput): Promise<FederatedIdentity>;

  /**
   * Find a federated identity by ID
   */
  findById(id: string): Promise<FederatedIdentity | null>;

  /**
   * Find a federated identity by provider and provider user ID
   * Used to look up local user from external identity
   */
  findByProviderIdentity(
    tenantId: string,
    providerId: string,
    providerUserId: string
  ): Promise<FederatedIdentity | null>;

  /**
   * Find all federated identities for a user
   * Used to show linked accounts in user settings
   */
  findByUser(tenantId: string, userId: string): Promise<FederatedIdentity[]>;

  /**
   * Update a federated identity (e.g., refresh provider data)
   */
  update(id: string, input: UpdateFederatedIdentityInput): Promise<FederatedIdentity>;

  /**
   * Delete (unlink) a federated identity
   */
  delete(id: string): Promise<void>;

  /**
   * Delete all federated identities for a user
   * Used when deleting a user account
   */
  deleteByUser(tenantId: string, userId: string): Promise<number>;

  /**
   * Delete all federated identities for a provider
   * Used when deleting an identity provider
   */
  deleteByProvider(tenantId: string, providerId: string): Promise<number>;
}
