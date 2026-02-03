import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { TokenResponse } from '../../types/oauth.js';
import type { AuthenticatedClient } from '../../types/client.js';
import type { IAuthorizationCodeStorage, IRefreshTokenStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { tokenService } from '../../services/token-service.js';
import { scopeService } from '../../services/scope-service.js';
import { verifyCodeChallenge } from '../../crypto/pkce.js';
import { GRANT_TYPE_AUTHORIZATION_CODE } from '../../config/constants.js';

export interface AuthorizationCodeHandlerOptions {
  authorizationCodeStorage: IAuthorizationCodeStorage;
  refreshTokenStorage: IRefreshTokenStorage;
  userAuthenticator?: IUserAuthenticator;
}

/**
 * Handle authorization code token exchange
 */
export function createAuthorizationCodeHandler(options: AuthorizationCodeHandlerOptions) {
  const { authorizationCodeStorage, refreshTokenStorage, userAuthenticator } = options;

  return async (c: Context<{ Variables: OAuthVariables }>): Promise<TokenResponse> => {
    const tenant = c.get('tenant');
    const signingKey = c.get('signingKey');
    const authenticatedClient = c.get('client') as AuthenticatedClient;
    const client = authenticatedClient.client;

    // Parse body
    const body = await c.req.parseBody();
    const code = body['code'] as string | undefined;
    const redirectUri = body['redirect_uri'] as string | undefined;
    const codeVerifier = body['code_verifier'] as string | undefined;

    // Validate required parameters
    if (!code) {
      throw OAuthError.invalidRequest('Missing code parameter');
    }

    if (!redirectUri) {
      throw OAuthError.invalidRequest('Missing redirect_uri parameter');
    }

    if (!codeVerifier) {
      throw OAuthError.invalidRequest('Missing code_verifier parameter (PKCE required)');
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_AUTHORIZATION_CODE)) {
      throw OAuthError.unauthorizedClient(
        'Client is not authorized for authorization code grant'
      );
    }

    // Consume authorization code atomically (prevents replay)
    const authCode = await authorizationCodeStorage.consume(tenant.id, code);

    if (!authCode) {
      throw OAuthError.invalidGrant('Invalid or expired authorization code');
    }

    // Validate client matches
    if (authCode.clientId !== client.clientId) {
      throw OAuthError.invalidGrant('Authorization code was issued to a different client');
    }

    // Validate redirect_uri matches (exact match required)
    if (authCode.redirectUri !== redirectUri) {
      throw OAuthError.invalidGrant('redirect_uri does not match');
    }

    // Verify PKCE code verifier
    if (!verifyCodeChallenge(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
      throw OAuthError.invalidGrant('Invalid code_verifier');
    }

    // Get user info if user authenticator is available
    let user;
    if (userAuthenticator?.getUserById) {
      user = await userAuthenticator.getUserById(tenant.id, authCode.userId);
    }

    if (!user) {
      // Create minimal user object from auth code
      user = { id: authCode.userId };
    }

    // Parse scopes from auth code
    const scopes = scopeService.parseScopes(authCode.scope);

    // Generate tokens
    const response = await tokenService.generateTokenResponse({
      tenant,
      signingKey,
      client,
      user,
      scopes,
      nonce: authCode.nonce,
      refreshTokenStorage,
    });

    return response;
  };
}
