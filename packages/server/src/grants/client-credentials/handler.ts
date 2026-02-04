import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { TokenResponse } from '../../types/oauth.js';
import type { AuthenticatedClient } from '../../types/client.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { tokenService } from '../../services/token-service.js';
import { scopeService } from '../../services/scope-service.js';
import { GRANT_TYPE_CLIENT_CREDENTIALS } from '../../config/constants.js';

/**
 * Handle client credentials token request
 *
 * RFC 6749 Section 4.4
 */
export function createClientCredentialsHandler() {
  return async (c: Context<{ Variables: OAuthVariables }>): Promise<TokenResponse> => {
    const tenant = c.get('tenant');
    const signingKey = c.get('signingKey');
    const authenticatedClient = c.get('client') as AuthenticatedClient;
    const client = authenticatedClient.client;

    // Client credentials only for confidential clients
    if (client.clientType !== 'confidential') {
      throw OAuthError.unauthorizedClient(
        'Client credentials grant requires a confidential client'
      );
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_CLIENT_CREDENTIALS)) {
      throw OAuthError.unauthorizedClient(
        'Client is not authorized for client credentials grant'
      );
    }

    // Parse and validate scopes from body
    const body = await c.req.parseBody();
    const requestedScope = body['scope'] as string | undefined;
    const requestedScopes = scopeService.parseScopes(requestedScope);

    // Validate scopes (client credentials don't get user scopes like 'openid')
    const filteredScopes = requestedScopes.filter(
      (scope) => !['openid', 'profile', 'email', 'offline_access'].includes(scope)
    );

    const validatedScopes = scopeService.validateScopes(filteredScopes, tenant, client);

    // Generate tokens (no refresh token for client credentials)
    const response = await tokenService.generateClientCredentialsTokens(
      tenant,
      signingKey,
      client,
      validatedScopes
    );

    return response;
  };
}
