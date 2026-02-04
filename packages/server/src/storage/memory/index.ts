import type { IStorage } from '../interfaces/index.js';
import { MemoryTenantStorage, MemorySigningKeyStorage } from './tenant-storage.js';
import { MemoryClientStorage } from './client-storage.js';
import { MemoryRefreshTokenStorage, MemoryRevokedTokenStorage } from './token-storage.js';
import { MemoryAuthorizationCodeStorage } from './authorization-code-storage.js';
import { MemoryDeviceCodeStorage } from './device-code-storage.js';
import { MemoryIdentityProviderStorage } from './identity-provider-storage.js';
import { MemoryFederatedIdentityStorage } from './federated-identity-storage.js';

export { MemoryTenantStorage, MemorySigningKeyStorage } from './tenant-storage.js';
export { MemoryClientStorage } from './client-storage.js';
export { MemoryRefreshTokenStorage, MemoryRevokedTokenStorage } from './token-storage.js';
export { MemoryAuthorizationCodeStorage } from './authorization-code-storage.js';
export { MemoryDeviceCodeStorage } from './device-code-storage.js';
export { MemoryIdentityProviderStorage } from './identity-provider-storage.js';
export { MemoryFederatedIdentityStorage } from './federated-identity-storage.js';

/**
 * Create a complete in-memory storage implementation
 */
export function createMemoryStorage(): IStorage {
  return {
    tenants: new MemoryTenantStorage(),
    signingKeys: new MemorySigningKeyStorage(),
    clients: new MemoryClientStorage(),
    refreshTokens: new MemoryRefreshTokenStorage(),
    revokedTokens: new MemoryRevokedTokenStorage(),
    authorizationCodes: new MemoryAuthorizationCodeStorage(),
    deviceCodes: new MemoryDeviceCodeStorage(),
    identityProviders: new MemoryIdentityProviderStorage(),
    federatedIdentities: new MemoryFederatedIdentityStorage(),
  };
}
