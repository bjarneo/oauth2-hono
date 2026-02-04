import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { createAuthorizeHandler } from '../../grants/authorization-code/authorize.js';

export interface AuthorizeRouteOptions {
  storage: IStorage;
  userAuthenticator: IUserAuthenticator;
}

/**
 * Create authorization endpoint routes
 */
export function createAuthorizeRoutes(options: AuthorizeRouteOptions) {
  const { storage, userAuthenticator } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  const authorizeHandler = createAuthorizeHandler({
    clientStorage: storage.clients,
    authorizationCodeStorage: storage.authorizationCodes,
    userAuthenticator,
  });

  // GET /authorize - Initial authorization request
  router.get('/', authorizeHandler);

  // POST /authorize - Form submission (consent, login redirect back)
  router.post('/', authorizeHandler);

  return router;
}
