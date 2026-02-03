import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { JWKSResponse } from '../../types/oauth.js';
import type { ISigningKeyStorage } from '../../storage/interfaces/index.js';
import { publicKeyToJwk } from '../../crypto/jwt.js';

export interface JWKSRouteOptions {
  signingKeyStorage: ISigningKeyStorage;
}

/**
 * Create JWKS endpoint
 *
 * GET /:tenant/.well-known/jwks.json
 */
export function createJWKSRoutes(options: JWKSRouteOptions) {
  const { signingKeyStorage } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  router.get('/', async (c) => {
    const tenant = c.get('tenant');

    // Get all signing keys for tenant
    const signingKeys = await signingKeyStorage.listByTenant(tenant.id);

    // Convert to JWK format
    const keys = await Promise.all(
      signingKeys
        .filter((key) => !key.expiresAt || key.expiresAt > new Date())
        .map((key) => publicKeyToJwk(key.publicKey, key.kid, key.algorithm))
    );

    const response: JWKSResponse = { keys };

    // Cache for 1 hour
    c.header('Cache-Control', 'public, max-age=3600');

    return c.json(response);
  });

  return router;
}
