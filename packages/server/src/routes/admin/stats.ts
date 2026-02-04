import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';

export interface StatsRoutesOptions {
  storage: IStorage;
}

export function createStatsRoutes(options: StatsRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // Get dashboard stats
  app.get('/', async (c) => {
    const tenants = await storage.tenants.list({});
    let clientCount = 0;

    // Count clients across all tenants
    for (const tenant of tenants) {
      const clients = await storage.clients.listByTenant(tenant.id);
      clientCount += clients.length;
    }

    return c.json({
      tenantCount: tenants.length,
      clientCount,
      activeRefreshTokens: 0, // TODO: Add count method to storage
      activeAuthorizationCodes: 0,
      activeDeviceCodes: 0,
      identityProviderCount: 0, // TODO: Add when IdP storage is implemented
    });
  });

  return app;
}
