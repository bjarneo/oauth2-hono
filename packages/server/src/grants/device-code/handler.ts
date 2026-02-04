import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { TokenResponse } from '../../types/oauth.js';
import type { AuthenticatedClient } from '../../types/client.js';
import type { IDeviceCodeStorage, IRefreshTokenStorage, IUserAuthenticator } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { tokenService } from '../../services/token-service.js';
import { scopeService } from '../../services/scope-service.js';
import { GRANT_TYPE_DEVICE_CODE } from '../../config/constants.js';

export interface DeviceCodeHandlerOptions {
  deviceCodeStorage: IDeviceCodeStorage;
  refreshTokenStorage: IRefreshTokenStorage;
  userAuthenticator?: IUserAuthenticator;
}

/**
 * Handle device code token request (polling)
 *
 * RFC 8628 Section 3.4-3.5
 */
export function createDeviceCodeHandler(options: DeviceCodeHandlerOptions) {
  const { deviceCodeStorage, refreshTokenStorage, userAuthenticator } = options;

  return async (c: Context<{ Variables: OAuthVariables }>): Promise<TokenResponse> => {
    const tenant = c.get('tenant');
    const signingKey = c.get('signingKey');
    const authenticatedClient = c.get('client') as AuthenticatedClient;
    const client = authenticatedClient.client;

    // Parse body
    const body = await c.req.parseBody();
    const deviceCodeValue = body['device_code'] as string | undefined;

    if (!deviceCodeValue) {
      throw OAuthError.invalidRequest('Missing device_code parameter');
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_DEVICE_CODE)) {
      throw OAuthError.unauthorizedClient(
        'Client is not authorized for device code grant'
      );
    }

    // Find device code
    const deviceCode = await deviceCodeStorage.findByValue(tenant.id, deviceCodeValue);

    if (!deviceCode) {
      throw OAuthError.invalidGrant('Invalid device code');
    }

    // Check if device code belongs to this client
    if (deviceCode.clientId !== client.clientId) {
      throw OAuthError.invalidGrant('Device code was issued to a different client');
    }

    // Check if expired
    if (deviceCode.expiresAt < new Date()) {
      await deviceCodeStorage.consume(deviceCode.id); // Clean up
      throw OAuthError.expiredToken();
    }

    // Check polling interval (rate limiting)
    const canPoll = await deviceCodeStorage.updateLastPolled(deviceCode.id);
    if (!canPoll) {
      throw OAuthError.slowDown();
    }

    // Check authorization status
    switch (deviceCode.status) {
      case 'pending':
        throw OAuthError.authorizationPending();

      case 'denied':
        await deviceCodeStorage.consume(deviceCode.id); // Clean up
        throw OAuthError.accessDenied('User denied authorization');

      case 'expired':
        await deviceCodeStorage.consume(deviceCode.id); // Clean up
        throw OAuthError.expiredToken();

      case 'authorized':
        // Continue to token generation
        break;

      default:
        throw OAuthError.serverError('Unknown device code status');
    }

    // Get user info
    let user;
    if (deviceCode.userId) {
      if (userAuthenticator?.getUserById) {
        user = await userAuthenticator.getUserById(tenant.id, deviceCode.userId);
      }
      if (!user) {
        user = { id: deviceCode.userId };
      }
    }

    if (!user) {
      throw OAuthError.serverError('Device code authorized but no user found');
    }

    // Consume the device code (single use)
    await deviceCodeStorage.consume(deviceCode.id);

    // Parse scopes
    const scopes = scopeService.parseScopes(deviceCode.scope);

    // Generate tokens
    const response = await tokenService.generateTokenResponse({
      tenant,
      signingKey,
      client,
      user,
      scopes,
      refreshTokenStorage,
    });

    return response;
  };
}
