import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { TokenResponse } from '../../types/oauth.js';
import type { IStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { clientAuthenticator } from '../../middleware/client-authenticator.js';
import { createAuthorizationCodeHandler } from '../../grants/authorization-code/handler.js';
import { createClientCredentialsHandler } from '../../grants/client-credentials/handler.js';
import { createRefreshTokenHandler } from '../../grants/refresh-token/handler.js';
import { createDeviceCodeHandler } from '../../grants/device-code/handler.js';
import {
  TOKEN_CACHE_CONTROL,
  TOKEN_PRAGMA,
  HEADER_CACHE_CONTROL,
  HEADER_PRAGMA,
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  GRANT_TYPE_DEVICE_CODE,
} from '../../config/constants.js';

export interface TokenRouteOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  tokenEndpointUrl?: string;
}

/**
 * Create token endpoint routes
 */
export function createTokenRoutes(options: TokenRouteOptions) {
  const { storage, userAuthenticator, tokenEndpointUrl } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  // Create grant handlers
  const authorizationCodeHandler = createAuthorizationCodeHandler({
    authorizationCodeStorage: storage.authorizationCodes,
    refreshTokenStorage: storage.refreshTokens,
    userAuthenticator,
  });

  const clientCredentialsHandler = createClientCredentialsHandler();

  const refreshTokenHandler = createRefreshTokenHandler({
    refreshTokenStorage: storage.refreshTokens,
    userAuthenticator,
  });

  const deviceCodeHandler = createDeviceCodeHandler({
    deviceCodeStorage: storage.deviceCodes,
    refreshTokenStorage: storage.refreshTokens,
    userAuthenticator,
  });

  // POST /token
  router.post(
    '/',
    // Client authentication
    clientAuthenticator({
      clientStorage: storage.clients,
      allowPublicClients: true, // Allow public clients for auth code with PKCE
      tokenEndpointUrl,
    }),
    async (c) => {
      // Set cache control headers
      c.header(HEADER_CACHE_CONTROL, TOKEN_CACHE_CONTROL);
      c.header(HEADER_PRAGMA, TOKEN_PRAGMA);

      // Parse grant type
      const body = await c.req.parseBody();
      const grantType = body['grant_type'] as string | undefined;

      if (!grantType) {
        throw OAuthError.invalidRequest('Missing grant_type parameter');
      }

      let response: TokenResponse;

      switch (grantType) {
        case GRANT_TYPE_AUTHORIZATION_CODE:
          response = await authorizationCodeHandler(c);
          break;

        case GRANT_TYPE_CLIENT_CREDENTIALS:
          response = await clientCredentialsHandler(c);
          break;

        case GRANT_TYPE_REFRESH_TOKEN:
          response = await refreshTokenHandler(c);
          break;

        case GRANT_TYPE_DEVICE_CODE:
          response = await deviceCodeHandler(c);
          break;

        default:
          throw OAuthError.unsupportedGrantType(`Unsupported grant type: ${grantType}`);
      }

      return c.json(response);
    }
  );

  return router;
}
