import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import type { IRefreshTokenStorageWithList } from './types.js';

export interface TokenRoutesOptions {
  storage: IStorage;
}

export function createTokenRoutes(options: TokenRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // List refresh tokens for a tenant
  app.get('/tenants/:tenantId/refresh-tokens', async (c) => {
    const tenantId = c.req.param('tenantId');
    const userId = c.req.query('userId');
    const clientId = c.req.query('clientId');
    const activeOnly = c.req.query('active') !== 'false';
    const limit = parseInt(c.req.query('limit') || '50');
    const page = parseInt(c.req.query('page') || '1');

    // Check if storage supports listing
    const refreshTokenStorage = storage.refreshTokens as IRefreshTokenStorageWithList;
    if (!refreshTokenStorage.listByTenant) {
      const tenant = await storage.tenants.findById(tenantId);
      if (!tenant) {
        return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
      }
      return c.json({
        data: [],
        total: 0,
        page,
        limit,
        totalPages: 0,
      });
    }

    // Parallel fetch: tenant validation and tokens list (async-parallel rule)
    const [tenant, tokens] = await Promise.all([
      storage.tenants.findById(tenantId),
      refreshTokenStorage.listByTenant(tenantId, {
        userId,
        clientId,
        activeOnly,
        limit,
        offset: (page - 1) * limit,
      }),
    ]);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    return c.json({
      data: tokens.items,
      total: tokens.total,
      page,
      limit,
      totalPages: Math.ceil(tokens.total / limit),
    });
  });

  // Revoke a specific refresh token
  app.post('/refresh-tokens/:id/revoke', async (c) => {
    const id = c.req.param('id');

    try {
      await storage.refreshTokens.revoke(id);
      return c.body(null, 204);
    } catch {
      return c.json({ error: 'not_found', message: 'Token not found' }, 404);
    }
  });

  // Revoke all tokens for a user in a tenant
  app.post('/tenants/:tenantId/refresh-tokens/revoke-by-user/:userId', async (c) => {
    const tenantId = c.req.param('tenantId');
    const userId = c.req.param('userId');

    const tenant = await storage.tenants.findById(tenantId);
    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    const revokedCount = await storage.refreshTokens.revokeByUser(tenantId, userId);
    return c.json({ revokedCount });
  });

  return app;
}
