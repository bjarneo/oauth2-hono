import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { optionalClientAuthenticator } from '../../middleware/client-authenticator.js';
import { decodeJwt, getJwtHeader } from '../../crypto/jwt.js';
import type { AccessTokenPayload } from '../../types/token.js';

export interface RevokeRouteOptions {
  storage: IStorage;
}

/**
 * Create token revocation endpoint routes
 *
 * RFC 7009
 */
export function createRevokeRoutes(options: RevokeRouteOptions) {
  const { storage } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  // POST /revoke
  router.post(
    '/',
    optionalClientAuthenticator({
      clientStorage: storage.clients,
    }),
    async (c) => {
      const tenant = c.get('tenant');
      const authenticatedClient = c.get('client');

      const body = await c.req.parseBody();
      const token = body['token'] as string | undefined;
      const tokenTypeHint = body['token_type_hint'] as string | undefined;

      if (!token) {
        throw OAuthError.invalidRequest('Missing token parameter');
      }

      // RFC 7009: Always return 200 OK, even if token is invalid
      // This prevents token fishing

      try {
        // Try to determine token type and revoke
        if (tokenTypeHint === 'refresh_token' || !tokenTypeHint) {
          // Try refresh token first
          const refreshToken = await storage.refreshTokens.findByValue(tenant.id, token);

          if (refreshToken) {
            // Verify client ownership (if client is authenticated)
            if (authenticatedClient && refreshToken.clientId !== authenticatedClient.client.clientId) {
              // Don't reveal token belongs to different client
              return c.json({});
            }

            // Revoke the token
            await storage.refreshTokens.revoke(refreshToken.id);
            return c.json({});
          }
        }

        if (tokenTypeHint === 'access_token' || !tokenTypeHint) {
          // Try to decode as JWT access token
          const header = getJwtHeader(token);
          const payload = decodeJwt<AccessTokenPayload>(token);

          if (header && payload && payload.jti) {
            // Verify tenant
            if (payload.tenant_id !== tenant.id) {
              return c.json({});
            }

            // Verify client ownership (if client is authenticated)
            if (authenticatedClient && payload.client_id !== authenticatedClient.client.clientId) {
              return c.json({});
            }

            // Add to revoked tokens list
            await storage.revokedTokens.revoke(
              tenant.id,
              payload.jti,
              'access_token',
              new Date(payload.exp * 1000)
            );
          }
        }
      } catch {
        // Ignore errors - RFC 7009 says always return 200
      }

      return c.json({});
    }
  );

  return router;
}
