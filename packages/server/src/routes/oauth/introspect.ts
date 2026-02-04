import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IntrospectionResponse } from '../../types/oauth.js';
import type { IStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { clientAuthenticator } from '../../middleware/client-authenticator.js';
import { getJwtHeader, verifyJwt } from '../../crypto/jwt.js';
import type { AccessTokenPayload } from '../../types/token.js';
import { TOKEN_TYPE_BEARER } from '../../config/constants.js';

export interface IntrospectRouteOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
}

/**
 * Create token introspection endpoint routes
 *
 * RFC 7662
 */
export function createIntrospectRoutes(options: IntrospectRouteOptions) {
  const { storage, userAuthenticator } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  // POST /introspect
  router.post(
    '/',
    // Require client authentication for introspection
    clientAuthenticator({
      clientStorage: storage.clients,
      allowPublicClients: false,
    }),
    async (c) => {
      const tenant = c.get('tenant');

      const body = await c.req.parseBody();
      const token = body['token'] as string | undefined;
      const tokenTypeHint = body['token_type_hint'] as string | undefined;

      if (!token) {
        throw OAuthError.invalidRequest('Missing token parameter');
      }

      // Inactive response for invalid tokens
      const inactive: IntrospectionResponse = { active: false };

      try {
        // Try refresh token first if hinted
        if (tokenTypeHint === 'refresh_token') {
          const refreshToken = await storage.refreshTokens.findByValue(tenant.id, token);

          if (refreshToken) {
            // Check if valid
            if (refreshToken.revokedAt || refreshToken.expiresAt < new Date()) {
              return c.json(inactive);
            }

            const response: IntrospectionResponse = {
              active: true,
              client_id: refreshToken.clientId,
              scope: refreshToken.scope,
              token_type: TOKEN_TYPE_BEARER,
              exp: Math.floor(refreshToken.expiresAt.getTime() / 1000),
              iat: Math.floor(refreshToken.issuedAt.getTime() / 1000),
              iss: tenant.issuer,
            };

            if (refreshToken.userId) {
              response.sub = refreshToken.userId;

              // Get username if available
              if (userAuthenticator?.getUserById) {
                const user = await userAuthenticator.getUserById(tenant.id, refreshToken.userId);
                if (user?.username) {
                  response.username = user.username;
                }
              }
            }

            return c.json(response);
          }
        }

        // Try as JWT access token
        const header = getJwtHeader(token);
        if (!header || !header.kid) {
          return c.json(inactive);
        }

        // Find signing key
        const signingKey = await storage.signingKeys.findByKid(tenant.id, header.kid);
        if (!signingKey) {
          return c.json(inactive);
        }

        // Verify token
        let payload: AccessTokenPayload;
        try {
          payload = await verifyJwt<AccessTokenPayload>(
            token,
            signingKey.publicKey,
            signingKey.algorithm,
            { issuer: tenant.issuer }
          );
        } catch {
          return c.json(inactive);
        }

        // Check if revoked
        if (payload.jti) {
          const isRevoked = await storage.revokedTokens.isRevoked(tenant.id, payload.jti);
          if (isRevoked) {
            return c.json(inactive);
          }
        }

        // Check tenant
        if (payload.tenant_id !== tenant.id) {
          return c.json(inactive);
        }

        const response: IntrospectionResponse = {
          active: true,
          scope: payload.scope,
          client_id: payload.client_id,
          token_type: TOKEN_TYPE_BEARER,
          exp: payload.exp,
          iat: payload.iat,
          nbf: payload.nbf,
          sub: payload.sub,
          aud: payload.aud,
          iss: payload.iss,
          jti: payload.jti,
        };

        // Get username if available
        if (payload.sub && userAuthenticator?.getUserById) {
          const user = await userAuthenticator.getUserById(tenant.id, payload.sub);
          if (user?.username) {
            response.username = user.username;
          }
        }

        return c.json(response);
      } catch {
        return c.json(inactive);
      }
    }
  );

  return router;
}
