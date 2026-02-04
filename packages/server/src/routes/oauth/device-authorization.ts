import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import { createDeviceAuthorizationHandler } from '../../grants/device-code/device-authorization.js';
import {
  TOKEN_CACHE_CONTROL,
  TOKEN_PRAGMA,
  HEADER_CACHE_CONTROL,
  HEADER_PRAGMA,
} from '../../config/constants.js';

export interface DeviceAuthorizationRouteOptions {
  storage: IStorage;
  verificationUri: string;
}

/**
 * Create device authorization endpoint routes
 *
 * RFC 8628
 */
export function createDeviceAuthorizationRoutes(options: DeviceAuthorizationRouteOptions) {
  const { storage, verificationUri } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  const handler = createDeviceAuthorizationHandler({
    clientStorage: storage.clients,
    deviceCodeStorage: storage.deviceCodes,
    verificationUri,
  });

  // POST /device_authorization
  router.post('/', async (c) => {
    // Set cache control headers
    c.header(HEADER_CACHE_CONTROL, TOKEN_CACHE_CONTROL);
    c.header(HEADER_PRAGMA, TOKEN_PRAGMA);

    const response = await handler(c);
    return c.json(response);
  });

  return router;
}
