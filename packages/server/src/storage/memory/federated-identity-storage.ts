import type {
  FederatedIdentity,
  CreateFederatedIdentityInput,
  UpdateFederatedIdentityInput,
  IFederatedIdentityStorage,
} from '../interfaces/federated-identity-storage.js';
import { generateId } from '../../crypto/index.js';

/**
 * In-memory federated identity storage implementation
 */
export class MemoryFederatedIdentityStorage implements IFederatedIdentityStorage {
  private identities = new Map<string, FederatedIdentity>();
  // Index for looking up by provider identity: `${tenantId}:${providerId}:${providerUserId}` -> id
  private providerIndex = new Map<string, string>();

  async create(input: CreateFederatedIdentityInput): Promise<FederatedIdentity> {
    const id = generateId();
    const now = new Date();

    const identity: FederatedIdentity = {
      id,
      tenantId: input.tenantId,
      userId: input.userId,
      providerId: input.providerId,
      providerUserId: input.providerUserId,
      providerUserData: input.providerUserData,
      createdAt: now,
      updatedAt: now,
    };

    this.identities.set(id, identity);
    this.providerIndex.set(
      `${input.tenantId}:${input.providerId}:${input.providerUserId}`,
      id
    );

    return identity;
  }

  async findById(id: string): Promise<FederatedIdentity | null> {
    return this.identities.get(id) ?? null;
  }

  async findByProviderIdentity(
    tenantId: string,
    providerId: string,
    providerUserId: string
  ): Promise<FederatedIdentity | null> {
    const id = this.providerIndex.get(`${tenantId}:${providerId}:${providerUserId}`);
    if (!id) return null;
    return this.identities.get(id) ?? null;
  }

  async findByUser(tenantId: string, userId: string): Promise<FederatedIdentity[]> {
    return Array.from(this.identities.values()).filter(
      (identity) => identity.tenantId === tenantId && identity.userId === userId
    );
  }

  async update(id: string, input: UpdateFederatedIdentityInput): Promise<FederatedIdentity> {
    const identity = this.identities.get(id);
    if (!identity) {
      throw new Error(`Federated identity not found: ${id}`);
    }

    const updated: FederatedIdentity = {
      ...identity,
      providerUserData: input.providerUserData ?? identity.providerUserData,
      updatedAt: new Date(),
    };

    this.identities.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<void> {
    const identity = this.identities.get(id);
    if (identity) {
      this.providerIndex.delete(
        `${identity.tenantId}:${identity.providerId}:${identity.providerUserId}`
      );
      this.identities.delete(id);
    }
  }

  async deleteByUser(tenantId: string, userId: string): Promise<number> {
    const toDelete = Array.from(this.identities.values()).filter(
      (identity) => identity.tenantId === tenantId && identity.userId === userId
    );

    for (const identity of toDelete) {
      this.providerIndex.delete(
        `${identity.tenantId}:${identity.providerId}:${identity.providerUserId}`
      );
      this.identities.delete(identity.id);
    }

    return toDelete.length;
  }

  async deleteByProvider(tenantId: string, providerId: string): Promise<number> {
    const toDelete = Array.from(this.identities.values()).filter(
      (identity) => identity.tenantId === tenantId && identity.providerId === providerId
    );

    for (const identity of toDelete) {
      this.providerIndex.delete(
        `${identity.tenantId}:${identity.providerId}:${identity.providerUserId}`
      );
      this.identities.delete(identity.id);
    }

    return toDelete.length;
  }
}
