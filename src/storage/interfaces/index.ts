export * from './tenant-storage.js';
export * from './client-storage.js';
export * from './token-storage.js';
export * from './authorization-code-storage.js';
export * from './device-code-storage.js';
export * from './user-storage.js';

import type { ITenantStorage, ISigningKeyStorage } from './tenant-storage.js';
import type { IClientStorage } from './client-storage.js';
import type { IRefreshTokenStorage, IRevokedTokenStorage } from './token-storage.js';
import type { IAuthorizationCodeStorage } from './authorization-code-storage.js';
import type { IDeviceCodeStorage } from './device-code-storage.js';
import type { IUserAuthenticator, IConsentStorage } from './user-storage.js';

/**
 * Complete storage interface for the OAuth server
 */
export interface IStorage {
  tenants: ITenantStorage;
  signingKeys: ISigningKeyStorage;
  clients: IClientStorage;
  refreshTokens: IRefreshTokenStorage;
  revokedTokens: IRevokedTokenStorage;
  authorizationCodes: IAuthorizationCodeStorage;
  deviceCodes: IDeviceCodeStorage;
}

/**
 * Storage factory options
 */
export interface StorageOptions {
  /**
   * User authenticator implementation
   * Required for authorization code and device code flows
   */
  userAuthenticator?: IUserAuthenticator;

  /**
   * Optional consent storage (if not using userAuthenticator's built-in consent)
   */
  consentStorage?: IConsentStorage;
}
