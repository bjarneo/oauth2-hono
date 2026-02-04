import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import type {
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  ClientAuthMethod,
  GrantType,
} from '../../types/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { generateSecureToken } from '../../crypto/random.js';
import { scopeService } from '../../services/scope-service.js';
import {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  GRANT_TYPE_DEVICE_CODE,
  RESPONSE_TYPE_CODE,
} from '../../config/constants.js';

export interface RegisterRoutesOptions {
  storage: IStorage;
  baseUrl: string;
  /**
   * Whether to allow open registration (no authentication)
   * If false, requires an initial access token
   */
  allowOpenRegistration?: boolean;
  /**
   * Initial access token for registration (if not allowing open registration)
   */
  initialAccessToken?: string;
  /**
   * Default scopes for new clients
   */
  defaultScopes?: string[];
  /**
   * Default grant types for new clients
   */
  defaultGrantTypes?: GrantType[];
}

/**
 * Validate redirect URIs
 */
function validateRedirectUris(uris: string[]): void {
  for (const uri of uris) {
    try {
      const parsed = new URL(uri);

      // localhost is allowed for development
      if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
        continue;
      }

      // Must use HTTPS for non-localhost URIs
      if (parsed.protocol !== 'https:') {
        throw OAuthError.invalidRequest(`Redirect URI must use HTTPS: ${uri}`);
      }

      // No fragments allowed
      if (parsed.hash) {
        throw OAuthError.invalidRequest(`Redirect URI must not contain fragment: ${uri}`);
      }
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw OAuthError.invalidRequest(`Invalid redirect URI: ${uri}`);
    }
  }
}

/**
 * Map grant types from request to internal format
 */
function mapGrantTypes(grantTypes: string[] | undefined): GrantType[] {
  if (!grantTypes || grantTypes.length === 0) {
    return [GRANT_TYPE_AUTHORIZATION_CODE];
  }

  const mapped: GrantType[] = [];

  for (const gt of grantTypes) {
    switch (gt) {
      case 'authorization_code':
        mapped.push(GRANT_TYPE_AUTHORIZATION_CODE);
        break;
      case 'client_credentials':
        mapped.push(GRANT_TYPE_CLIENT_CREDENTIALS);
        break;
      case 'refresh_token':
        mapped.push(GRANT_TYPE_REFRESH_TOKEN);
        break;
      case 'urn:ietf:params:oauth:grant-type:device_code':
        mapped.push(GRANT_TYPE_DEVICE_CODE);
        break;
      default:
        throw OAuthError.invalidRequest(`Unsupported grant type: ${gt}`);
    }
  }

  return mapped;
}

/**
 * Determine client type and auth method from request
 */
function determineClientTypeAndAuth(
  request: ClientRegistrationRequest
): { clientType: 'public' | 'confidential'; authMethod: ClientAuthMethod } {
  const authMethod = request.token_endpoint_auth_method || 'client_secret_basic';

  // Public clients use 'none' authentication
  if (authMethod === 'none') {
    return { clientType: 'public', authMethod: 'none' };
  }

  // All other methods are for confidential clients
  return { clientType: 'confidential', authMethod };
}

/**
 * Create Dynamic Client Registration endpoint
 *
 * POST /:tenant/register
 *
 * RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
 */
export function createRegisterRoutes(options: RegisterRoutesOptions) {
  const {
    storage,
    baseUrl,
    allowOpenRegistration = false,
    initialAccessToken,
    defaultScopes = ['openid', 'profile', 'email'],
    defaultGrantTypes = [GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_REFRESH_TOKEN],
  } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  // POST /register - Register a new client
  router.post('/', async (c) => {
    const tenant = c.get('tenant');

    // Check authentication if not allowing open registration
    if (!allowOpenRegistration) {
      const authHeader = c.req.header('Authorization');

      if (!authHeader?.startsWith('Bearer ')) {
        throw OAuthError.invalidRequest('Authorization required for client registration');
      }

      const token = authHeader.slice(7);

      if (initialAccessToken && token !== initialAccessToken) {
        throw OAuthError.invalidToken('Invalid initial access token');
      }
    }

    // Parse request body
    const request = await c.req.json<ClientRegistrationRequest>();

    // Validate redirect URIs (required)
    if (!request.redirect_uris || request.redirect_uris.length === 0) {
      throw OAuthError.invalidRequest('redirect_uris is required');
    }

    validateRedirectUris(request.redirect_uris);

    // Validate post-logout redirect URIs if provided
    if (request.post_logout_redirect_uris) {
      validateRedirectUris(request.post_logout_redirect_uris);
    }

    // Determine client type and auth method
    const { clientType, authMethod } = determineClientTypeAndAuth(request);

    // Map grant types
    const grantTypes = request.grant_types
      ? mapGrantTypes(request.grant_types)
      : defaultGrantTypes;

    // Parse scopes
    const requestedScopes = request.scope
      ? scopeService.parseScopes(request.scope)
      : defaultScopes;

    // Validate scopes against tenant
    const validScopes = requestedScopes.filter((scope) =>
      tenant.allowedScopes.includes(scope)
    );

    // Generate registration access token
    const registrationAccessToken = generateSecureToken(32);

    // Create the client
    const { client, clientSecret } = await storage.clients.create({
      tenantId: tenant.id,
      clientType,
      authMethod,
      name: request.client_name || 'Unnamed Client',
      description: undefined,
      logoUri: request.logo_uri,
      clientUri: request.client_uri,
      policyUri: request.policy_uri,
      tosUri: request.tos_uri,
      redirectUris: request.redirect_uris,
      allowedGrants: grantTypes,
      allowedScopes: validScopes,
      defaultScopes: validScopes,
      jwksUri: request.jwks_uri,
      jwks: request.jwks,
      requireConsent: true,
      firstParty: false,
      postLogoutRedirectUris: request.post_logout_redirect_uris,
      backchannelLogoutUri: request.backchannel_logout_uri,
      backchannelLogoutSessionRequired: request.backchannel_logout_session_required,
      frontchannelLogoutUri: request.frontchannel_logout_uri,
      frontchannelLogoutSessionRequired: request.frontchannel_logout_session_required,
      contacts: request.contacts,
      softwareId: request.software_id,
      softwareVersion: request.software_version,
      softwareStatement: request.software_statement,
      metadata: {
        registrationAccessToken,
      },
    });

    // Build response
    const registrationClientUri = `${baseUrl}/${tenant.slug}/register/${client.clientId}`;

    const response: ClientRegistrationResponse = {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      registration_access_token: registrationAccessToken,
      registration_client_uri: registrationClientUri,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: client.authMethod,
      grant_types: grantTypes,
      response_types: grantTypes.includes(GRANT_TYPE_AUTHORIZATION_CODE)
        ? [RESPONSE_TYPE_CODE]
        : [],
      scope: scopeService.formatScopes(validScopes),
    };

    // Add secret for confidential clients
    if (clientSecret) {
      response.client_secret = clientSecret;
      response.client_secret_expires_at = 0; // Never expires
    }

    // Add optional fields
    if (request.client_name) response.client_name = request.client_name;
    if (request.client_uri) response.client_uri = request.client_uri;
    if (request.logo_uri) response.logo_uri = request.logo_uri;
    if (request.contacts) response.contacts = request.contacts;
    if (request.tos_uri) response.tos_uri = request.tos_uri;
    if (request.policy_uri) response.policy_uri = request.policy_uri;
    if (request.jwks_uri) response.jwks_uri = request.jwks_uri;
    if (request.jwks) response.jwks = request.jwks;
    if (request.software_id) response.software_id = request.software_id;
    if (request.software_version) response.software_version = request.software_version;
    if (request.post_logout_redirect_uris) {
      response.post_logout_redirect_uris = request.post_logout_redirect_uris;
    }
    if (request.backchannel_logout_uri) {
      response.backchannel_logout_uri = request.backchannel_logout_uri;
    }
    if (request.backchannel_logout_session_required !== undefined) {
      response.backchannel_logout_session_required = request.backchannel_logout_session_required;
    }
    if (request.frontchannel_logout_uri) {
      response.frontchannel_logout_uri = request.frontchannel_logout_uri;
    }
    if (request.frontchannel_logout_session_required !== undefined) {
      response.frontchannel_logout_session_required = request.frontchannel_logout_session_required;
    }

    c.status(201);
    return c.json(response);
  });

  // GET /register/:client_id - Read client configuration
  router.get('/:client_id', async (c) => {
    const tenant = c.get('tenant');
    const clientId = c.req.param('client_id');

    // Verify registration access token
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      throw OAuthError.invalidRequest('Authorization required');
    }

    const token = authHeader.slice(7);

    // Get client
    const client = await storage.clients.findByClientId(tenant.id, clientId);
    if (!client) {
      throw OAuthError.invalidRequest('Client not found');
    }

    // Verify token
    const storedToken = client.metadata?.registrationAccessToken as string | undefined;
    if (!storedToken || token !== storedToken) {
      throw OAuthError.invalidToken('Invalid registration access token');
    }

    // Build response (similar to registration response but without secret)
    const response: ClientRegistrationResponse = {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: client.authMethod,
      grant_types: client.allowedGrants,
      response_types: client.allowedGrants.includes(GRANT_TYPE_AUTHORIZATION_CODE)
        ? [RESPONSE_TYPE_CODE]
        : [],
      scope: scopeService.formatScopes(client.allowedScopes),
    };

    if (client.name) response.client_name = client.name;
    if (client.clientUri) response.client_uri = client.clientUri;
    if (client.logoUri) response.logo_uri = client.logoUri;
    if (client.contacts) response.contacts = client.contacts;
    if (client.tosUri) response.tos_uri = client.tosUri;
    if (client.policyUri) response.policy_uri = client.policyUri;
    if (client.jwksUri) response.jwks_uri = client.jwksUri;
    if (client.jwks) response.jwks = client.jwks;
    if (client.softwareId) response.software_id = client.softwareId;
    if (client.softwareVersion) response.software_version = client.softwareVersion;
    if (client.postLogoutRedirectUris) {
      response.post_logout_redirect_uris = client.postLogoutRedirectUris;
    }
    if (client.backchannelLogoutUri) {
      response.backchannel_logout_uri = client.backchannelLogoutUri;
    }
    if (client.backchannelLogoutSessionRequired !== undefined) {
      response.backchannel_logout_session_required = client.backchannelLogoutSessionRequired;
    }
    if (client.frontchannelLogoutUri) {
      response.frontchannel_logout_uri = client.frontchannelLogoutUri;
    }
    if (client.frontchannelLogoutSessionRequired !== undefined) {
      response.frontchannel_logout_session_required = client.frontchannelLogoutSessionRequired;
    }

    return c.json(response);
  });

  // DELETE /register/:client_id - Delete client registration
  router.delete('/:client_id', async (c) => {
    const tenant = c.get('tenant');
    const clientId = c.req.param('client_id');

    // Verify registration access token
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      throw OAuthError.invalidRequest('Authorization required');
    }

    const token = authHeader.slice(7);

    // Get client
    const client = await storage.clients.findByClientId(tenant.id, clientId);
    if (!client) {
      throw OAuthError.invalidRequest('Client not found');
    }

    // Verify token
    const storedToken = client.metadata?.registrationAccessToken as string | undefined;
    if (!storedToken || token !== storedToken) {
      throw OAuthError.invalidToken('Invalid registration access token');
    }

    // Delete client
    await storage.clients.delete(client.id);

    c.status(204);
    return c.body(null);
  });

  return router;
}
