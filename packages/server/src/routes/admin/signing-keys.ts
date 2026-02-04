import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';

const createSigningKeySchema = z.object({
  algorithm: z.enum(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']).optional(),
  isPrimary: z.boolean().optional(),
});

export interface SigningKeyRoutesOptions {
  storage: IStorage;
}

export function createSigningKeyRoutes(options: SigningKeyRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // List signing keys for a tenant
  app.get('/tenants/:tenantId/signing-keys', async (c) => {
    const tenantId = c.req.param('tenantId');

    // Parallel fetch: tenant validation and keys list (async-parallel rule)
    const [tenant, keys] = await Promise.all([
      storage.tenants.findById(tenantId),
      storage.signingKeys.listByTenant(tenantId),
    ]);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    return c.json(keys);
  });

  // Create signing key
  app.post('/tenants/:tenantId/signing-keys', zValidator('json', createSigningKeySchema), async (c) => {
    const tenantId = c.req.param('tenantId');
    const input = c.req.valid('json');

    const tenant = await storage.tenants.findById(tenantId);
    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    const key = await storage.signingKeys.create({
      tenantId,
      algorithm: input.algorithm,
      isPrimary: input.isPrimary,
    });

    return c.json(key, 201);
  });

  // Rotate signing keys
  app.post('/tenants/:tenantId/signing-keys/rotate', async (c) => {
    const tenantId = c.req.param('tenantId');

    // Parallel fetch: tenant validation and current primary key (async-parallel rule)
    const [tenant, currentPrimary] = await Promise.all([
      storage.tenants.findById(tenantId),
      storage.signingKeys.getPrimary(tenantId),
    ]);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }
    const algorithm = currentPrimary?.algorithm || 'RS256';

    // Create new primary key
    const newKey = await storage.signingKeys.create({
      tenantId,
      algorithm: algorithm as 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512',
      isPrimary: true,
    });

    return c.json({
      newKey,
      previousPrimaryKey: currentPrimary,
    });
  });

  // Set signing key as primary
  app.put('/signing-keys/:id/set-primary', async (c) => {
    const id = c.req.param('id');

    const existing = await storage.signingKeys.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Signing key not found' }, 404);
    }

    const key = await storage.signingKeys.setPrimary(id);
    return c.json(key);
  });

  // Delete signing key
  app.delete('/signing-keys/:id', async (c) => {
    const id = c.req.param('id');

    const existing = await storage.signingKeys.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Signing key not found' }, 404);
    }

    // Check if this is the only key - don't allow deletion
    const allKeys = await storage.signingKeys.listByTenant(existing.tenantId);
    if (allKeys.length === 1) {
      return c.json({ error: 'bad_request', message: 'Cannot delete the only signing key' }, 400);
    }

    // Don't allow deleting primary key if there are other keys
    if (existing.isPrimary) {
      return c.json({ error: 'bad_request', message: 'Cannot delete primary key. Set another key as primary first.' }, 400);
    }

    await storage.signingKeys.delete(id);
    return c.body(null, 204);
  });

  return app;
}
