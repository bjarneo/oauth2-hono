import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { OpenIDConfiguration } from '../../types/oauth.js';
import {
  RESPONSE_TYPE_CODE,
  CODE_CHALLENGE_METHOD_S256,
  CLIENT_AUTH_BASIC,
  CLIENT_AUTH_POST,
  CLIENT_AUTH_PRIVATE_KEY_JWT,
  CLIENT_AUTH_NONE,
} from '../../config/constants.js';

/**
 * Create OpenID Connect discovery endpoint
 *
 * GET /:tenant/.well-known/openid-configuration
 */
export function createOpenIDConfigurationRoutes() {
  const router = new Hono<{ Variables: OAuthVariables }>();

  router.get('/', (c) => {
    const tenant = c.get('tenant');
    const baseUrl = tenant.issuer;

    const config: OpenIDConfiguration = {
      issuer: tenant.issuer,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      revocation_endpoint: `${baseUrl}/revoke`,
      introspection_endpoint: `${baseUrl}/introspect`,
      device_authorization_endpoint: `${baseUrl}/device_authorization`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: [RESPONSE_TYPE_CODE],
      grant_types_supported: tenant.allowedGrants,
      token_endpoint_auth_methods_supported: [
        CLIENT_AUTH_BASIC,
        CLIENT_AUTH_POST,
        CLIENT_AUTH_PRIVATE_KEY_JWT,
        CLIENT_AUTH_NONE,
      ],
      code_challenge_methods_supported: [CODE_CHALLENGE_METHOD_S256],
      scopes_supported: tenant.allowedScopes,
      claims_supported: [
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'name',
        'email',
        'email_verified',
        'picture',
      ],
    };

    // Cache for 1 hour
    c.header('Cache-Control', 'public, max-age=3600');

    return c.json(config);
  });

  return router;
}
