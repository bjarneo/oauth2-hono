import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { ERROR_INVALID_REQUEST, ERROR_SERVER_ERROR } from '../../errors/error-codes.js';
import { generateRandomBase64Url } from '../../crypto/random.js';
import { getProviderConfig } from './providers.js';

export interface InitiateRoutesOptions {
  storage: IStorage;
  baseUrl: string;
}

/**
 * Federation state stored temporarily during the OAuth flow
 */
export interface FederationState {
  tenantId: string;
  providerId: string;
  originalState?: string;
  redirectUri?: string;
  clientId?: string;
  scope?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  createdAt: number;
}

// In-memory state store (should be Redis/DB in production)
const federationStates = new Map<string, FederationState>();

// Cleanup old states periodically
setInterval(() => {
  const now = Date.now();
  const maxAge = 10 * 60 * 1000; // 10 minutes
  for (const [key, state] of federationStates.entries()) {
    if (now - state.createdAt > maxAge) {
      federationStates.delete(key);
    }
  }
}, 60 * 1000);

export function saveFederationState(state: FederationState): string {
  const stateKey = generateRandomBase64Url(32);
  federationStates.set(stateKey, state);
  return stateKey;
}

export function getFederationState(stateKey: string): FederationState | undefined {
  const state = federationStates.get(stateKey);
  if (state) {
    federationStates.delete(stateKey); // One-time use
  }
  return state;
}

/**
 * Create federation initiation routes
 */
export function createInitiateRoutes(options: InitiateRoutesOptions): Hono<{ Variables: OAuthVariables }> {
  const { storage, baseUrl } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  /**
   * GET /federate/:idpSlug
   * Initiate federated login with an external identity provider
   */
  app.get('/:idpSlug', async (c) => {
    const tenant = c.get('tenant');
    const idpSlug = c.req.param('idpSlug');

    // Check if identity provider storage is available
    if (!storage.identityProviders) {
      throw new OAuthError(
        ERROR_SERVER_ERROR,
        'Identity provider federation is not configured'
      );
    }

    // Find the identity provider
    const idp = await storage.identityProviders.findBySlug(tenant.id, idpSlug);
    if (!idp) {
      throw new OAuthError(
        ERROR_INVALID_REQUEST,
        `Identity provider not found: ${idpSlug}`
      );
    }

    if (!idp.enabled) {
      throw new OAuthError(
        ERROR_INVALID_REQUEST,
        `Identity provider is disabled: ${idpSlug}`
      );
    }

    // Get provider configuration
    const providerConfig = getProviderConfig(idp.template, {
      authorizationEndpoint: idp.authorizationEndpoint,
      tokenEndpoint: idp.tokenEndpoint,
      userinfoEndpoint: idp.userinfoEndpoint,
      jwksUri: idp.jwksUri,
      issuer: idp.issuer,
    });

    if (!providerConfig.authorizationEndpoint) {
      throw new OAuthError(
        ERROR_SERVER_ERROR,
        'Identity provider authorization endpoint not configured'
      );
    }

    // Get optional parameters from the request
    const originalState = c.req.query('state');
    const redirectUri = c.req.query('redirect_uri');
    const clientId = c.req.query('client_id');
    const scope = c.req.query('scope');
    const nonce = c.req.query('nonce');
    const codeChallenge = c.req.query('code_challenge');
    const codeChallengeMethod = c.req.query('code_challenge_method');

    // Save state for callback
    const stateKey = saveFederationState({
      tenantId: tenant.id,
      providerId: idp.id,
      originalState,
      redirectUri,
      clientId,
      scope,
      nonce,
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now(),
    });

    // Build callback URL
    const callbackUrl = `${baseUrl}/${tenant.slug}/federate/${idpSlug}/callback`;

    // Build authorization URL
    const authUrl = new URL(providerConfig.authorizationEndpoint);
    authUrl.searchParams.set('client_id', idp.clientId);
    authUrl.searchParams.set('redirect_uri', callbackUrl);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', stateKey);

    // Set scopes
    const scopes = idp.scopes.length > 0 ? idp.scopes : providerConfig.defaultScopes;
    authUrl.searchParams.set('scope', scopes.join(' '));

    // Add nonce for OIDC providers
    if (providerConfig.supportsOidc && nonce) {
      authUrl.searchParams.set('nonce', nonce);
    }

    // Redirect to identity provider
    return c.redirect(authUrl.toString());
  });

  return app;
}
