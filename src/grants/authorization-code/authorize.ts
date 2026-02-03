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
  RESPONSE_MODE_QUERY,
  RESPONSE_MODE_FRAGMENT,
  RESPONSE_MODE_FORM_POST,
} from '../../config/constants.js';

export interface AuthorizeHandlerOptions {
  clientStorage: IClientStorage;
  authorizationCodeStorage: IAuthorizationCodeStorage;
  userAuthenticator: IUserAuthenticator;
}

type ResponseMode = 'query' | 'fragment' | 'form_post';

/**
 * Build authorization response based on response_mode
 */
function buildAuthorizationResponse(
  c: Context,
  redirectUri: string,
  params: Record<string, string>,
  responseMode: ResponseMode
): Response {
  if (responseMode === RESPONSE_MODE_FORM_POST) {
    // Return HTML form that auto-submits via POST
    const hiddenInputs = Object.entries(params)
      .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
      .join('\n      ');

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorization Response</title>
</head>
<body onload="document.forms[0].submit()">
  <noscript>
    <p>JavaScript is required. Please click the button below to continue.</p>
  </noscript>
  <form method="POST" action="${escapeHtml(redirectUri)}">
    ${hiddenInputs}
    <noscript>
      <button type="submit">Continue</button>
    </noscript>
  </form>
</body>
</html>`;

    return c.html(html);
  }

  const url = new URL(redirectUri);

  if (responseMode === RESPONSE_MODE_FRAGMENT) {
    // Add parameters to fragment
    const fragment = new URLSearchParams(params).toString();
    url.hash = fragment;
  } else {
    // Default: add parameters to query string
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
  }

  return c.redirect(url.toString());
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
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
    const responseMode = (params['response_mode'] as ResponseMode | undefined) || RESPONSE_MODE_QUERY;
    const claims = params['claims'] as string | undefined;
    const acrValues = params['acr_values'] as string | undefined;
    // Note: loginHint can be passed to the authenticator if needed
    void params['login_hint'];
    const prompt = params['prompt'] as string | undefined;
    const maxAge = params['max_age'] as string | undefined;

    // Validate response_mode
    if (
      responseMode &&
      responseMode !== RESPONSE_MODE_QUERY &&
      responseMode !== RESPONSE_MODE_FRAGMENT &&
      responseMode !== RESPONSE_MODE_FORM_POST
    ) {
      throw OAuthError.invalidRequest(`Invalid response_mode: ${responseMode}`);
    }

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
      const errorParams: Record<string, string> = {
        error: error.code,
        iss: tenant.issuer,
      };
      if (error.description) {
        errorParams.error_description = error.description;
      }
      if (state) {
        errorParams.state = state;
      }

      return buildAuthorizationResponse(c, redirectUri, errorParams, responseMode);
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

    // Validate claims parameter if provided
    if (claims) {
      try {
        JSON.parse(claims); // Validate JSON format
      } catch {
        return redirectWithError(
          OAuthError.invalidRequest('Invalid claims parameter: must be valid JSON', state)
        );
      }
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

    // Handle prompt=none (silent authentication)
    if (prompt === 'none') {
      // Try to authenticate without user interaction
      const authResult = await userAuthenticator.authenticate(c);
      if (!authResult.authenticated) {
        return redirectWithError(
          OAuthError.loginRequired('User is not authenticated', state)
        );
      }
    }

    // Authenticate user
    const authResult = await userAuthenticator.authenticate(c);
    if (!authResult.authenticated) {
      // Redirect to login page
      return c.redirect(authResult.redirectTo);
    }

    const user = authResult.user;

    // Check max_age if provided
    if (maxAge && user.authTime) {
      const maxAgeSeconds = parseInt(maxAge, 10);
      const authAge = Math.floor(Date.now() / 1000) - user.authTime;
      if (authAge > maxAgeSeconds) {
        // Re-authentication required
        return redirectWithError(
          OAuthError.loginRequired('Authentication is too old', state)
        );
      }
    }

    // Handle prompt=login (force re-authentication)
    if (prompt === 'login') {
      // This would require the authenticator to force a new login
      // For now, we just proceed with the current authentication
    }

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

      // Handle prompt=consent (force consent prompt)
      const forceConsent = prompt === 'consent';

      if (needsConsent || forceConsent) {
        // Handle prompt=none with consent required
        if (prompt === 'none') {
          return redirectWithError(
            OAuthError.consentRequired('User consent is required', state)
          );
        }

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
              id: client.clientId,
              name: client.name,
              description: client.description,
              logo_uri: client.logoUri,
              client_uri: client.clientUri,
              policy_uri: client.policyUri,
              tos_uri: client.tosUri,
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
              response_mode: responseMode,
              claims,
              acr_values: acrValues,
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
      responseMode,
      claims,
      acr: acrValues,
      expiresAt,
    });

    // Build authorization response
    const responseParams: Record<string, string> = {
      code,
      iss: tenant.issuer, // RFC 9700: Include issuer in authorization response
    };

    if (state) {
      responseParams.state = state;
    }

    return buildAuthorizationResponse(c, redirectUri, responseParams, responseMode);
  };
}
