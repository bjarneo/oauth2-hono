import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { createInitiateRoutes } from './initiate.js';
import { createCallbackRoutes, type CallbackRoutesOptions } from './callback.js';

export interface FederationRoutesOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  baseUrl: string;
  /**
   * Custom callback for handling federated login user creation/linking
   */
  onFederatedLogin?: CallbackRoutesOptions['onFederatedLogin'];
}

/**
 * Create federation routes for external identity provider authentication
 *
 * Routes:
 * - GET /federate/:idpSlug - Initiate federated login
 * - GET /federate/:idpSlug/callback - Handle IdP callback
 */
export function createFederationRoutes(
  options: FederationRoutesOptions
): Hono<{ Variables: OAuthVariables }> {
  const { storage, userAuthenticator, baseUrl, onFederatedLogin } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // Mount initiate routes
  app.route('/', createInitiateRoutes({ storage, baseUrl }));

  // Mount callback routes
  app.route('/', createCallbackRoutes({
    storage,
    userAuthenticator,
    baseUrl,
    onFederatedLogin,
  }));

  return app;
}

export * from './initiate.js';
export * from './callback.js';
export * from './providers.js';
