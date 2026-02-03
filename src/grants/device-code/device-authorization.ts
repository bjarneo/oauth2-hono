import type { Context } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { DeviceAuthorizationResponse } from '../../types/oauth.js';
import type { IClientStorage, IDeviceCodeStorage } from '../../storage/interfaces/index.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { scopeService } from '../../services/scope-service.js';
import { GRANT_TYPE_DEVICE_CODE } from '../../config/constants.js';

export interface DeviceAuthorizationHandlerOptions {
  clientStorage: IClientStorage;
  deviceCodeStorage: IDeviceCodeStorage;
  verificationUri: string; // Base URI for user verification (e.g., https://example.com/device)
}

/**
 * Handle device authorization request (POST /:tenant/device_authorization)
 *
 * RFC 8628 Section 3.1-3.2
 */
export function createDeviceAuthorizationHandler(options: DeviceAuthorizationHandlerOptions) {
  const { clientStorage, deviceCodeStorage, verificationUri } = options;

  return async (c: Context<{ Variables: OAuthVariables }>): Promise<DeviceAuthorizationResponse> => {
    const tenant = c.get('tenant');

    // Parse body
    const body = await c.req.parseBody();
    const clientId = body['client_id'] as string | undefined;
    const requestedScope = body['scope'] as string | undefined;

    if (!clientId) {
      throw OAuthError.invalidRequest('Missing client_id parameter');
    }

    // Look up client
    const client = await clientStorage.findByClientId(tenant.id, clientId);
    if (!client) {
      throw OAuthError.invalidClient('Unknown client_id');
    }

    // Check if grant type is allowed
    if (!client.allowedGrants.includes(GRANT_TYPE_DEVICE_CODE)) {
      throw OAuthError.unauthorizedClient(
        'Client is not authorized for device code grant'
      );
    }

    // Parse and validate scopes
    const requestedScopes = scopeService.parseScopes(requestedScope);
    const validatedScopes = scopeService.validateScopes(requestedScopes, tenant, client);

    // Create device code
    const expiresAt = new Date(Date.now() + tenant.deviceCodeTtl * 1000);

    const { deviceCodeValue, userCode } = await deviceCodeStorage.create({
      tenantId: tenant.id,
      clientId: client.clientId,
      scope: scopeService.formatScopes(validatedScopes),
      expiresAt,
      interval: tenant.deviceCodeInterval,
    });

    // Build verification URI with user code
    const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;

    return {
      device_code: deviceCodeValue,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: verificationUriComplete,
      expires_in: tenant.deviceCodeTtl,
      interval: tenant.deviceCodeInterval,
    };
  };
}
