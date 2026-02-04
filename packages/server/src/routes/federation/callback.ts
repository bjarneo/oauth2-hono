import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import {
  ERROR_INVALID_REQUEST,
  ERROR_SERVER_ERROR,
  ERROR_ACCESS_DENIED,
} from '../../errors/error-codes.js';
import { decrypt } from '../../crypto/encrypt.js';
import { getProviderConfig, defaultAttributeMappings } from './providers.js';
import { getFederationState } from './initiate.js';

export interface CallbackRoutesOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  baseUrl: string;
  /**
   * Callback to handle user creation/linking
   * If not provided, uses default behavior based on federated identity storage
   */
  onFederatedLogin?: (params: {
    tenantId: string;
    providerId: string;
    providerUserId: string;
    providerUserData: Record<string, unknown>;
    existingUserId?: string;
  }) => Promise<{ userId: string; isNewUser: boolean }>;
}

/**
 * Token response from identity provider
 */
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/**
 * Extract user attribute using dot notation path
 */
function extractAttribute(data: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let value: unknown = data;
  for (const part of parts) {
    if (value && typeof value === 'object' && part in value) {
      value = (value as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return value;
}

/**
 * Create federation callback routes
 */
export function createCallbackRoutes(options: CallbackRoutesOptions): Hono<{ Variables: OAuthVariables }> {
  const { storage, baseUrl, onFederatedLogin } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  /**
   * GET /federate/:idpSlug/callback
   * Handle callback from external identity provider
   */
  app.get('/:idpSlug/callback', async (c) => {
    const tenant = c.get('tenant');
    const idpSlug = c.req.param('idpSlug');

    // Check for error from IdP
    const error = c.req.query('error');
    if (error) {
      const errorDescription = c.req.query('error_description');
      throw new OAuthError(
        ERROR_ACCESS_DENIED,
        `Identity provider error: ${error}${errorDescription ? ` - ${errorDescription}` : ''}`
      );
    }

    // Get authorization code and state
    const code = c.req.query('code');
    const stateKey = c.req.query('state');

    if (!code) {
      throw new OAuthError(ERROR_INVALID_REQUEST, 'Missing authorization code');
    }

    if (!stateKey) {
      throw new OAuthError(ERROR_INVALID_REQUEST, 'Missing state parameter');
    }

    // Retrieve and validate state
    const federationState = getFederationState(stateKey);
    if (!federationState) {
      throw new OAuthError(ERROR_INVALID_REQUEST, 'Invalid or expired state');
    }

    if (federationState.tenantId !== tenant.id) {
      throw new OAuthError(ERROR_INVALID_REQUEST, 'State tenant mismatch');
    }

    // Check if identity provider storage is available
    if (!storage.identityProviders) {
      throw new OAuthError(
        ERROR_SERVER_ERROR,
        'Identity provider federation is not configured'
      );
    }

    // Find the identity provider
    const idp = await storage.identityProviders.findById(federationState.providerId);
    if (!idp) {
      throw new OAuthError(
        ERROR_INVALID_REQUEST,
        `Identity provider not found`
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

    if (!providerConfig.tokenEndpoint) {
      throw new OAuthError(
        ERROR_SERVER_ERROR,
        'Identity provider token endpoint not configured'
      );
    }

    // Build callback URL for token exchange
    const callbackUrl = `${baseUrl}/${tenant.slug}/federate/${idpSlug}/callback`;

    // Decrypt client secret
    let clientSecret: string;
    try {
      clientSecret = decrypt(idp.clientSecretEncrypted);
    } catch {
      throw new OAuthError(ERROR_SERVER_ERROR, 'Failed to decrypt client secret');
    }

    // Exchange code for tokens
    const tokenParams = new URLSearchParams();
    tokenParams.set('grant_type', 'authorization_code');
    tokenParams.set('code', code);
    tokenParams.set('redirect_uri', callbackUrl);
    tokenParams.set('client_id', idp.clientId);
    tokenParams.set('client_secret', clientSecret);

    let tokenResponse: TokenResponse;
    try {
      const response = await fetch(providerConfig.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: tokenParams.toString(),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        console.error('Token exchange failed:', errorBody);
        throw new OAuthError(
          ERROR_SERVER_ERROR,
          'Failed to exchange authorization code for tokens'
        );
      }

      // Handle different response content types
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        tokenResponse = (await response.json()) as TokenResponse;
      } else {
        // Some providers (like GitHub) return form-urlencoded
        const text = await response.text();
        const params = new URLSearchParams(text);
        tokenResponse = {
          access_token: params.get('access_token') || '',
          token_type: params.get('token_type') || 'bearer',
          scope: params.get('scope') || undefined,
        };
      }
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      console.error('Token exchange error:', err);
      throw new OAuthError(ERROR_SERVER_ERROR, 'Token exchange failed');
    }

    if (!tokenResponse.access_token) {
      throw new OAuthError(ERROR_SERVER_ERROR, 'No access token in response');
    }

    // Fetch user info
    let userInfo: Record<string, unknown> = {};
    if (providerConfig.userinfoEndpoint) {
      try {
        const userInfoResponse = await fetch(providerConfig.userinfoEndpoint, {
          headers: {
            Authorization: `Bearer ${tokenResponse.access_token}`,
            Accept: 'application/json',
          },
        });

        if (userInfoResponse.ok) {
          userInfo = (await userInfoResponse.json()) as Record<string, unknown>;
        }
      } catch (err) {
        console.error('UserInfo fetch error:', err);
        // Continue without userinfo - we have the access token
      }
    }

    // For GitHub, also fetch email if not in profile
    if (idp.template === 'github' && !userInfo.email) {
      try {
        const emailResponse = await fetch('https://api.github.com/user/emails', {
          headers: {
            Authorization: `Bearer ${tokenResponse.access_token}`,
            Accept: 'application/json',
          },
        });

        if (emailResponse.ok) {
          const emails = (await emailResponse.json()) as Array<{
            email: string;
            primary: boolean;
            verified: boolean;
          }>;
          const primaryEmail = emails.find((e) => e.primary && e.verified);
          if (primaryEmail) {
            userInfo.email = primaryEmail.email;
          }
        }
      } catch {
        // Continue without email
      }
    }

    // Apply attribute mapping
    const attributeMapping = idp.attributeMapping ||
      (idp.template ? defaultAttributeMappings[idp.template] : undefined) ||
      {};

    const mappedUser: Record<string, unknown> = {
      raw: userInfo,
    };

    for (const [localAttr, providerPath] of Object.entries(attributeMapping)) {
      const value = extractAttribute(userInfo, providerPath);
      if (value !== undefined) {
        mappedUser[localAttr] = value;
      }
    }

    // Get provider user ID
    const providerUserId = String(
      mappedUser.id || userInfo.sub || userInfo.id || ''
    );
    if (!providerUserId) {
      throw new OAuthError(ERROR_SERVER_ERROR, 'Could not determine provider user ID');
    }

    // Handle user creation/linking
    let userId: string;
    let isNewUser = false;

    if (onFederatedLogin) {
      // Use custom handler
      const result = await onFederatedLogin({
        tenantId: tenant.id,
        providerId: idp.id,
        providerUserId,
        providerUserData: mappedUser,
      });
      userId = result.userId;
      isNewUser = result.isNewUser;
    } else if (storage.federatedIdentities) {
      // Use federated identity storage
      const existing = await storage.federatedIdentities.findByProviderIdentity(
        tenant.id,
        idp.id,
        providerUserId
      );

      if (existing) {
        userId = existing.userId;
        // Update provider data
        await storage.federatedIdentities.update(existing.id, {
          providerUserData: mappedUser,
        });
      } else {
        // Create new federated identity
        // In a real system, you'd create/find a user first
        // For now, use the provider user ID as the local user ID
        userId = `federated:${idp.slug}:${providerUserId}`;
        isNewUser = true;
        await storage.federatedIdentities.create({
          tenantId: tenant.id,
          userId,
          providerId: idp.id,
          providerUserId,
          providerUserData: mappedUser,
        });
      }
    } else {
      // No storage - just use provider user ID
      userId = `federated:${idp.slug}:${providerUserId}`;
    }

    // Build response
    // If there was an original redirect URI, redirect back with the user info
    if (federationState.redirectUri) {
      const redirectUrl = new URL(federationState.redirectUri);

      // Add user info to redirect
      redirectUrl.searchParams.set('federated_user_id', userId);
      redirectUrl.searchParams.set('provider', idp.slug);

      if (federationState.originalState) {
        redirectUrl.searchParams.set('state', federationState.originalState);
      }

      return c.redirect(redirectUrl.toString());
    }

    // Return JSON response with user info
    return c.json({
      success: true,
      user_id: userId,
      is_new_user: isNewUser,
      provider: idp.slug,
      provider_user_id: providerUserId,
      user_data: {
        email: mappedUser.email,
        name: mappedUser.name,
        picture: mappedUser.picture,
      },
    });
  });

  return app;
}
