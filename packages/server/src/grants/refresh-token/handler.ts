import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { TokenResponse } from '../../types/oauth.js';
import type { AuthenticatedClient } from '../../types/client.js';
import type { IRefreshTokenStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { tokenService } from '../../services/token-service.js';
import { scopeService } from '../../services/scope-service.js';
import { GRANT_TYPE_REFRESH_TOKEN } from '../../config/constants.js';

export interface RefreshTokenHandlerOptions {
  refreshTokenStorage: IRefreshTokenStorage;
  userAuthenticator?: IUserAuthenticator;
}

/**
 * Handle refresh token grant
 *
 * RFC 6749 Section 6
 *
 * Implements refresh token rotation with replay detection:
 * - Each refresh token can only be used once
 * - A new refresh token is issued with each refresh
 * - If a revoked token is used, the entire token family is revoked
 */
export function createRefreshTokenHandler(options: RefreshTokenHandlerOptions) {
  const { refreshTokenStorage, userAuthenticator } = options;

  return async (c: Context<{ Variables: OAuthVariables }>): Promise<TokenResponse> => {
    const tenant = c.get('tenant');
    const signingKey = c.get('signingKey');
    const authenticatedClient = c.get('client') as AuthenticatedClient;
    const client = authenticatedClient.client;

    // Parse body
    const body = await c.req.parseBody();
    const refreshTokenValue = body['refresh_token'] as string | undefined;
    const requestedScope = body['scope'] as string | undefined;

    if (!refreshTokenValue) {
      throw OAuthError.invalidRequest('Missing refresh_token parameter');
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_REFRESH_TOKEN)) {
      throw OAuthError.unauthorizedClient(
        'Client is not authorized for refresh token grant'
      );
    }

    // Find the refresh token
    const refreshToken = await refreshTokenStorage.findByValue(tenant.id, refreshTokenValue);

    if (!refreshToken) {
      throw OAuthError.invalidGrant('Invalid refresh token');
    }

    // Check if token belongs to this client
    if (refreshToken.clientId !== client.clientId) {
      throw OAuthError.invalidGrant('Refresh token was issued to a different client');
    }

    // Check if token is expired
    if (refreshToken.expiresAt < new Date()) {
      throw OAuthError.invalidGrant('Refresh token has expired');
    }

    // Check if token is revoked - if so, this might be a replay attack
    if (refreshToken.revokedAt) {
      // Potential replay attack! Revoke the entire token family
      await refreshTokenStorage.revokeFamily(tenant.id, refreshToken.familyId);
      throw OAuthError.invalidGrant('Refresh token has been revoked');
    }

    // Revoke the current token (rotation)
    await refreshTokenStorage.revoke(refreshToken.id);

    // Handle scope downgrading
    const originalScopes = scopeService.parseScopes(refreshToken.scope);
    let newScopes = originalScopes;

    if (requestedScope) {
      const requestedScopes = scopeService.parseScopes(requestedScope);
      // Can only request a subset of original scopes
      const invalidScopes = requestedScopes.filter(
        (scope) => !originalScopes.includes(scope)
      );

      if (invalidScopes.length > 0) {
        throw OAuthError.invalidScope(
          `Cannot request scopes not in original grant: ${invalidScopes.join(', ')}`
        );
      }

      newScopes = requestedScopes;
    }

    // Get user info if available
    let user;
    if (refreshToken.userId) {
      if (userAuthenticator?.getUserById) {
        user = await userAuthenticator.getUserById(tenant.id, refreshToken.userId);
      }
      if (!user) {
        user = { id: refreshToken.userId };
      }
    }

    // Generate new tokens with refresh token rotation
    const response = await tokenService.generateTokenResponse({
      tenant,
      signingKey,
      client,
      user,
      scopes: newScopes,
      refreshTokenStorage,
      parentRefreshTokenId: refreshToken.id,
      familyId: refreshToken.familyId, // Keep same family for rotation tracking
    });

    return response;
  };
}
