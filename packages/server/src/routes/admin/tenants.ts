import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';

const createTenantSchema = z.object({
  name: z.string().min(1),
  slug: z.string().min(1).regex(/^[a-z0-9-]+$/),
  issuer: z.string().optional(),
  allowedGrants: z.array(z.string()).optional(),
  allowedScopes: z.array(z.string()).optional(),
  accessTokenTtl: z.number().positive().optional(),
  refreshTokenTtl: z.number().positive().optional(),
  authorizationCodeTtl: z.number().positive().optional(),
  deviceCodeTtl: z.number().positive().optional(),
  deviceCodeInterval: z.number().positive().optional(),
  allowedRedirectUriPatterns: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const updateTenantSchema = z.object({
  name: z.string().min(1).optional(),
  issuer: z.string().optional(),
  allowedGrants: z.array(z.string()).optional(),
  allowedScopes: z.array(z.string()).optional(),
  accessTokenTtl: z.number().positive().optional(),
  refreshTokenTtl: z.number().positive().optional(),
  authorizationCodeTtl: z.number().positive().optional(),
  deviceCodeTtl: z.number().positive().optional(),
  deviceCodeInterval: z.number().positive().optional(),
  allowedRedirectUriPatterns: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

export interface TenantRoutesOptions {
  storage: IStorage;
}

export function createTenantRoutes(options: TenantRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // List tenants
  app.get('/', async (c) => {
    const limit = parseInt(c.req.query('limit') || '50');
    const page = parseInt(c.req.query('page') || '1');
    const offset = (page - 1) * limit;

    // Parallel fetch: paginated list and total count (async-parallel rule)
    const [tenants, allTenants] = await Promise.all([
      storage.tenants.list({ limit, offset }),
      storage.tenants.list({}),
    ]);
    const total = allTenants.length;

    return c.json({
      data: tenants,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  });

  // Get tenant by ID
  app.get('/:id', async (c) => {
    const id = c.req.param('id');
    const tenant = await storage.tenants.findById(id);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    return c.json(tenant);
  });

  // Get tenant stats
  app.get('/:id/stats', async (c) => {
    const id = c.req.param('id');
    const tenant = await storage.tenants.findById(id);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    // Parallel fetch: clients and signing keys (async-parallel rule)
    const [clients, signingKeys] = await Promise.all([
      storage.clients.listByTenant(id),
      storage.signingKeys.listByTenant(id),
    ]);

    // Count active tokens - we need to add list methods to interfaces
    // For now, return basic stats
    return c.json({
      clientCount: clients.length,
      signingKeyCount: signingKeys.length,
      activeRefreshTokens: 0, // TODO: Add listByTenant to IRefreshTokenStorage
      activeAuthorizationCodes: 0,
      activeDeviceCodes: 0,
      identityProviderCount: 0, // TODO: Add when IdP storage is implemented
    });
  });

  // Create tenant
  app.post('/', zValidator('json', createTenantSchema), async (c) => {
    const input = c.req.valid('json');

    try {
      const tenant = await storage.tenants.create(input as Parameters<typeof storage.tenants.create>[0]);
      return c.json(tenant, 201);
    } catch (error) {
      if (error instanceof Error && error.message.includes('unique')) {
        return c.json({ error: 'conflict', message: 'Tenant with this slug already exists' }, 409);
      }
      throw error;
    }
  });

  // Update tenant
  app.put('/:id', zValidator('json', updateTenantSchema), async (c) => {
    const id = c.req.param('id');
    const input = c.req.valid('json');

    const existing = await storage.tenants.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    const tenant = await storage.tenants.update(id, input as Parameters<typeof storage.tenants.update>[1]);
    return c.json(tenant);
  });

  // Delete tenant
  app.delete('/:id', async (c) => {
    const id = c.req.param('id');

    const existing = await storage.tenants.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    await storage.tenants.delete(id);
    return c.body(null, 204);
  });

  return app;
}
