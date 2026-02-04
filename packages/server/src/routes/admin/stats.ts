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

    // Parallel fetch: clients for all tenants (async-parallel rule - eliminates N+1)
    const clientLists = await Promise.all(
      tenants.map((tenant) => storage.clients.listByTenant(tenant.id))
    );
    const clientCount = clientLists.reduce((sum, clients) => sum + clients.length, 0);

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
