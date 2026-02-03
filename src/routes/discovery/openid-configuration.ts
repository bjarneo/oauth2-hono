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
  RESPONSE_MODE_QUERY,
  RESPONSE_MODE_FRAGMENT,
  RESPONSE_MODE_FORM_POST,
  SIGNING_ALGORITHM_RS256,
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
      // Core endpoints
      issuer: tenant.issuer,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,

      // Token management endpoints
      revocation_endpoint: `${baseUrl}/revoke`,
      introspection_endpoint: `${baseUrl}/introspect`,

      // Device authorization
      device_authorization_endpoint: `${baseUrl}/device_authorization`,

      // Session management
      end_session_endpoint: `${baseUrl}/end_session`,

      // Dynamic registration
      registration_endpoint: `${baseUrl}/register`,

      // Supported features
      response_types_supported: [RESPONSE_TYPE_CODE],
      response_modes_supported: [
        RESPONSE_MODE_QUERY,
        RESPONSE_MODE_FRAGMENT,
        RESPONSE_MODE_FORM_POST,
      ],
      grant_types_supported: tenant.allowedGrants,
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [SIGNING_ALGORITHM_RS256],
      token_endpoint_auth_methods_supported: [
        CLIENT_AUTH_BASIC,
        CLIENT_AUTH_POST,
        CLIENT_AUTH_PRIVATE_KEY_JWT,
        CLIENT_AUTH_NONE,
      ],
      code_challenge_methods_supported: [CODE_CHALLENGE_METHOD_S256],

      // Scopes and claims
      scopes_supported: tenant.allowedScopes,
      claims_supported: [
        // Standard claims
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'acr',
        'amr',
        'azp',
        // Profile scope claims
        'name',
        'given_name',
        'family_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'profile',
        'picture',
        'website',
        'gender',
        'birthdate',
        'zoneinfo',
        'locale',
        'updated_at',
        // Email scope claims
        'email',
        'email_verified',
        // Address scope claims
        'address',
        // Phone scope claims
        'phone_number',
        'phone_number_verified',
      ],

      // Feature support flags
      claims_parameter_supported: true,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,

      // Logout support
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true,
      frontchannel_logout_supported: true,
      frontchannel_logout_session_supported: true,
    };

    // Cache for 1 hour
    c.header('Cache-Control', 'public, max-age=3600');

    return c.json(config);
  });

  return router;
}
