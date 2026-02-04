import type { IStorage } from '../interfaces/index.js';
import { initializePrisma } from './client.js';
import { PrismaTenantStorage, PrismaSigningKeyStorage } from './repositories/tenant-repository.js';
import { PrismaClientStorage } from './repositories/client-repository.js';
import { PrismaRefreshTokenStorage, PrismaRevokedTokenStorage } from './repositories/token-repository.js';
import { PrismaAuthorizationCodeStorage } from './repositories/authorization-code-repository.js';
import { PrismaDeviceCodeStorage } from './repositories/device-code-repository.js';
import { PrismaIdentityProviderStorage } from './repositories/identity-provider-repository.js';
import { PrismaFederatedIdentityStorage } from './repositories/federated-identity-repository.js';

export { initializePrisma, getPrisma, closePrisma } from './client.js';
export { PrismaTenantStorage, PrismaSigningKeyStorage } from './repositories/tenant-repository.js';
export { PrismaClientStorage } from './repositories/client-repository.js';
export { PrismaRefreshTokenStorage, PrismaRevokedTokenStorage } from './repositories/token-repository.js';
export { PrismaAuthorizationCodeStorage } from './repositories/authorization-code-repository.js';
export { PrismaDeviceCodeStorage } from './repositories/device-code-repository.js';
export { PrismaIdentityProviderStorage } from './repositories/identity-provider-repository.js';
export { PrismaFederatedIdentityStorage } from './repositories/federated-identity-repository.js';

/**
 * Create a complete Prisma storage implementation
 */
export function createPrismaStorage(): IStorage {
  initializePrisma();

  return {
    tenants: new PrismaTenantStorage(),
    signingKeys: new PrismaSigningKeyStorage(),
    clients: new PrismaClientStorage(),
    refreshTokens: new PrismaRefreshTokenStorage(),
    revokedTokens: new PrismaRevokedTokenStorage(),
    authorizationCodes: new PrismaAuthorizationCodeStorage(),
    deviceCodes: new PrismaDeviceCodeStorage(),
    identityProviders: new PrismaIdentityProviderStorage(),
    federatedIdentities: new PrismaFederatedIdentityStorage(),
  };
}
