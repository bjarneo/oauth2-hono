import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IClientStorage, IAuthorizationCodeStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { scopeService } from '../../services/scope-service.js';
import { isValidCodeChallenge } from '../../crypto/pkce.js';
import {
  RESPONSE_TYPE_CODE,
  CODE_CHALLENGE_METHOD_S256,
  GRANT_TYPE_AUTHORIZATION_CODE,
} from '../../config/constants.js';

export interface AuthorizeHandlerOptions {
  clientStorage: IClientStorage;
  authorizationCodeStorage: IAuthorizationCodeStorage;
  userAuthenticator: IUserAuthenticator;
}

/**
 * Handle the authorization endpoint (GET/POST /:tenant/authorize)
 *
 * This implements the authorization request flow:
 * 1. Validate the request parameters
 * 2. Authenticate the user (redirect to login if needed)
 * 3. Check/request user consent
 * 4. Generate authorization code
 * 5. Redirect to client with code
 */
export function createAuthorizeHandler(options: AuthorizeHandlerOptions) {
  const { clientStorage, authorizationCodeStorage, userAuthenticator } = options;

  return async (c: Context<{ Variables: OAuthVariables }>) => {
    const tenant = c.get('tenant');

    // Extract parameters (from query for GET, from body for POST)
    const params = c.req.method === 'GET'
      ? Object.fromEntries(new URL(c.req.url).searchParams)
      : await c.req.parseBody();

    const responseType = params['response_type'] as string | undefined;
    const clientId = params['client_id'] as string | undefined;
    const redirectUri = params['redirect_uri'] as string | undefined;
    const scope = params['scope'] as string | undefined;
    const state = params['state'] as string | undefined;
    const codeChallenge = params['code_challenge'] as string | undefined;
    const codeChallengeMethod = params['code_challenge_method'] as string | undefined;
    const nonce = params['nonce'] as string | undefined;

    // Validate required parameters (before redirect_uri validation)
    if (!clientId) {
      throw OAuthError.invalidRequest('Missing client_id parameter');
    }

    // Look up client
    const client = await clientStorage.findByClientId(tenant.id, clientId);
    if (!client) {
      throw OAuthError.invalidRequest('Unknown client_id');
    }

    // Validate redirect_uri (must be exact match)
    if (!redirectUri) {
      throw OAuthError.invalidRequest('Missing redirect_uri parameter');
    }

    if (!client.redirectUris.includes(redirectUri)) {
      // Don't redirect on invalid redirect_uri - security risk
      throw OAuthError.invalidRequest('Invalid redirect_uri');
    }

    // Helper to redirect with error
    const redirectWithError = (error: OAuthError) => {
      const url = new URL(redirectUri);
      url.searchParams.set('error', error.code);
      if (error.description) {
        url.searchParams.set('error_description', error.description);
      }
      if (state) {
        url.searchParams.set('state', state);
      }
      // RFC 9700: Include issuer in error responses
      url.searchParams.set('iss', tenant.issuer);
      return c.redirect(url.toString());
    };

    // Validate response_type
    if (responseType !== RESPONSE_TYPE_CODE) {
      return redirectWithError(
        OAuthError.unsupportedResponseType('Only "code" response type is supported', state)
      );
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_AUTHORIZATION_CODE)) {
      return redirectWithError(
        OAuthError.unauthorizedClient('Client is not authorized for authorization code grant', state)
      );
    }

    // Validate PKCE (required per RFC 9700)
    if (!codeChallenge) {
      return redirectWithError(
        OAuthError.invalidRequest('Missing code_challenge parameter (PKCE required)', state)
      );
    }

    if (codeChallengeMethod !== CODE_CHALLENGE_METHOD_S256) {
      return redirectWithError(
        OAuthError.invalidRequest('Only S256 code_challenge_method is supported', state)
      );
    }

    if (!isValidCodeChallenge(codeChallenge)) {
      return redirectWithError(
        OAuthError.invalidRequest('Invalid code_challenge format', state)
      );
    }

    // Parse and validate scopes
    const requestedScopes = scopeService.parseScopes(scope);
    let validatedScopes: string[];
    try {
      validatedScopes = scopeService.validateScopes(requestedScopes, tenant, client);
    } catch (error) {
      if (error instanceof OAuthError) {
        return redirectWithError(error);
      }
      throw error;
    }

    // Authenticate user
    const authResult = await userAuthenticator.authenticate(c);
    if (!authResult.authenticated) {
      // Redirect to login page
      return c.redirect(authResult.redirectTo);
    }

    const user = authResult.user;

    // Check consent (skip for first-party apps)
    if (!client.firstParty && client.requireConsent !== false) {
      const existingConsent = await userAuthenticator.getConsent(
        tenant.id,
        user.id,
        client.clientId
      );

      // Check if existing consent covers all requested scopes
      const needsConsent =
        !existingConsent ||
        !validatedScopes.every((scope) => existingConsent.includes(scope));

      if (needsConsent) {
        // Check if this is a consent submission (POST with consent=true)
        if (c.req.method === 'POST' && params['consent'] === 'true') {
          // User granted consent - save it
          await userAuthenticator.saveConsent(
            tenant.id,
            user.id,
            client.clientId,
            validatedScopes
          );
        } else if (c.req.method === 'POST' && params['consent'] === 'false') {
          // User denied consent
          return redirectWithError(OAuthError.accessDenied('User denied consent', state));
        } else {
          // Need to show consent page
          // Return a JSON response that the frontend can use to render a consent page
          // In a real implementation, you'd render an HTML consent form
          return c.json({
            consent_required: true,
            client: {
              name: client.name,
              description: client.description,
            },
            scopes: validatedScopes,
            user: {
              id: user.id,
              name: user.name,
            },
            // Include original params for form submission
            params: {
              response_type: responseType,
              client_id: clientId,
              redirect_uri: redirectUri,
              scope: scopeService.formatScopes(validatedScopes),
              state,
              code_challenge: codeChallenge,
              code_challenge_method: codeChallengeMethod,
              nonce,
            },
          });
        }
      }
    }

    // Generate authorization code
    const expiresAt = new Date(Date.now() + tenant.authorizationCodeTtl * 1000);

    const { value: code } = await authorizationCodeStorage.create({
      tenantId: tenant.id,
      clientId: client.clientId,
      userId: user.id,
      redirectUri,
      scope: scopeService.formatScopes(validatedScopes),
      codeChallenge,
      codeChallengeMethod: CODE_CHALLENGE_METHOD_S256,
      nonce,
      state,
      expiresAt,
    });

    // Redirect to client with authorization code
    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    if (state) {
      url.searchParams.set('state', state);
    }
    // RFC 9700: Include issuer in authorization response
    url.searchParams.set('iss', tenant.issuer);

    return c.redirect(url.toString());
  };
}
