import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';

const createClientSchema = z.object({
  clientType: z.enum(['confidential', 'public']),
  authMethod: z.enum(['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'none']),
  name: z.string().min(1),
  description: z.string().optional(),
  logoUri: z.string().url().optional(),
  clientUri: z.string().url().optional(),
  policyUri: z.string().url().optional(),
  tosUri: z.string().url().optional(),
  redirectUris: z.array(z.string()),
  allowedGrants: z.array(z.string()),
  allowedScopes: z.array(z.string()),
  defaultScopes: z.array(z.string()).optional(),
  jwksUri: z.string().url().optional(),
  jwks: z.object({ keys: z.array(z.any()) }).optional(),
  accessTokenTtl: z.number().positive().optional(),
  refreshTokenTtl: z.number().positive().optional(),
  requireConsent: z.boolean().optional(),
  firstParty: z.boolean().optional(),
  postLogoutRedirectUris: z.array(z.string()).optional(),
  backchannelLogoutUri: z.string().url().optional(),
  backchannelLogoutSessionRequired: z.boolean().optional(),
  frontchannelLogoutUri: z.string().url().optional(),
  frontchannelLogoutSessionRequired: z.boolean().optional(),
  contacts: z.array(z.string()).optional(),
  softwareId: z.string().optional(),
  softwareVersion: z.string().optional(),
  softwareStatement: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const updateClientSchema = createClientSchema.partial().omit({ clientType: true, authMethod: true });

export interface ClientRoutesOptions {
  storage: IStorage;
}

export function createClientRoutes(options: ClientRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // List clients for a tenant
  app.get('/tenants/:tenantId/clients', async (c) => {
    const tenantId = c.req.param('tenantId');
    const limit = parseInt(c.req.query('limit') || '50');
    const page = parseInt(c.req.query('page') || '1');
    const offset = (page - 1) * limit;

    const tenant = await storage.tenants.findById(tenantId);
    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    const clients = await storage.clients.listByTenant(tenantId, { limit, offset });
    const allClients = await storage.clients.listByTenant(tenantId);
    const total = allClients.length;

    return c.json({
      data: clients,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  });

  // Create client
  app.post('/tenants/:tenantId/clients', zValidator('json', createClientSchema), async (c) => {
    const tenantId = c.req.param('tenantId');
    const input = c.req.valid('json');

    const tenant = await storage.tenants.findById(tenantId);
    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    const { client, clientSecret } = await storage.clients.create({
      tenantId,
      ...input,
    } as Parameters<typeof storage.clients.create>[0]);

    return c.json(
      {
        ...client,
        clientSecret, // Only included on creation
      },
      201
    );
  });

  // Get client by ID or clientId
  app.get('/clients/:id', async (c) => {
    const id = c.req.param('id');

    // First try to find by internal ID
    let client = await storage.clients.findById(id);

    // If not found, try to find by clientId across all tenants
    if (!client) {
      const tenants = await storage.tenants.list();
      for (const tenant of tenants) {
        client = await storage.clients.findByClientId(tenant.id, id);
        if (client) break;
      }
    }

    if (!client) {
      return c.json({ error: 'not_found', message: 'Client not found' }, 404);
    }

    return c.json(client);
  });

  // Update client
  app.put('/clients/:id', zValidator('json', updateClientSchema), async (c) => {
    const id = c.req.param('id');
    const input = c.req.valid('json');

    // First try to find by internal ID
    let existing = await storage.clients.findById(id);

    // If not found, try to find by clientId across all tenants
    if (!existing) {
      const tenants = await storage.tenants.list();
      for (const tenant of tenants) {
        existing = await storage.clients.findByClientId(tenant.id, id);
        if (existing) break;
      }
    }

    if (!existing) {
      return c.json({ error: 'not_found', message: 'Client not found' }, 404);
    }

    const client = await storage.clients.update(existing.id, input as Parameters<typeof storage.clients.update>[1]);
    return c.json(client);
  });

  // Delete client
  app.delete('/clients/:id', async (c) => {
    const id = c.req.param('id');

    // First try to find by internal ID
    let existing = await storage.clients.findById(id);

    // If not found, try to find by clientId across all tenants
    if (!existing) {
      const tenants = await storage.tenants.list();
      for (const tenant of tenants) {
        existing = await storage.clients.findByClientId(tenant.id, id);
        if (existing) break;
      }
    }

    if (!existing) {
      return c.json({ error: 'not_found', message: 'Client not found' }, 404);
    }

    await storage.clients.delete(existing.id);
    return c.body(null, 204);
  });

  // Regenerate client secret
  app.post('/clients/:id/regenerate-secret', async (c) => {
    const id = c.req.param('id');

    // First try to find by internal ID
    let existing = await storage.clients.findById(id);

    // If not found, try to find by clientId across all tenants
    if (!existing) {
      const tenants = await storage.tenants.list();
      for (const tenant of tenants) {
        existing = await storage.clients.findByClientId(tenant.id, id);
        if (existing) break;
      }
    }

    if (!existing) {
      return c.json({ error: 'not_found', message: 'Client not found' }, 404);
    }

    if (existing.clientType === 'public') {
      return c.json({ error: 'bad_request', message: 'Public clients do not have secrets' }, 400);
    }

    const clientSecret = await storage.clients.regenerateSecret(existing.id);
    return c.json({ clientSecret });
  });

  return app;
}
