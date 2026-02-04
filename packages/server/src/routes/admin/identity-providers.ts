import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import type { IIdentityProviderStorage } from '../../storage/interfaces/identity-provider-storage.js';

const createIdentityProviderSchema = z.object({
  name: z.string().min(1),
  slug: z.string().min(1).regex(/^[a-z0-9-]+$/),
  type: z.enum(['oidc', 'oauth2', 'saml']).optional().default('oidc'),
  template: z.enum([
    'google', 'github', 'microsoft', 'apple', 'facebook', 'twitter', 'linkedin',
    'generic_oidc', 'generic_oauth2'
  ]).optional(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  issuer: z.string().optional(),
  authorizationEndpoint: z.string().url().optional(),
  tokenEndpoint: z.string().url().optional(),
  userinfoEndpoint: z.string().url().optional(),
  jwksUri: z.string().url().optional(),
  scopes: z.array(z.string()).optional(),
  attributeMapping: z.object({
    id: z.string().optional(),
    email: z.string().optional(),
    name: z.string().optional(),
    givenName: z.string().optional(),
    familyName: z.string().optional(),
    picture: z.string().optional(),
    emailVerified: z.string().optional(),
    locale: z.string().optional(),
  }).optional(),
  enabled: z.boolean().optional().default(true),
  displayOrder: z.number().optional(),
  iconUrl: z.string().url().optional(),
  buttonText: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const updateIdentityProviderSchema = createIdentityProviderSchema.partial().omit({ slug: true });

export interface IdentityProviderRoutesOptions {
  storage: IStorage;
}

export function createIdentityProviderRoutes(options: IdentityProviderRoutesOptions) {
  const { storage } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // Get storage - may not be implemented yet
  const getIdpStorage = (): IIdentityProviderStorage | null => {
    return (storage as { identityProviders?: IIdentityProviderStorage }).identityProviders || null;
  };

  // List identity providers for a tenant
  app.get('/tenants/:tenantId/identity-providers', async (c) => {
    const tenantId = c.req.param('tenantId');
    const idpStorage = getIdpStorage();

    if (!idpStorage) {
      // Early return if storage not configured - no need to validate tenant
      const tenant = await storage.tenants.findById(tenantId);
      if (!tenant) {
        return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
      }
      return c.json([]);
    }

    // Parallel fetch: tenant validation and providers list (async-parallel rule)
    const [tenant, providers] = await Promise.all([
      storage.tenants.findById(tenantId),
      idpStorage.listByTenant(tenantId),
    ]);

    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    return c.json(providers);
  });

  // Create identity provider
  app.post('/tenants/:tenantId/identity-providers', zValidator('json', createIdentityProviderSchema), async (c) => {
    const tenantId = c.req.param('tenantId');
    const input = c.req.valid('json');
    const idpStorage = getIdpStorage();

    const tenant = await storage.tenants.findById(tenantId);
    if (!tenant) {
      return c.json({ error: 'not_found', message: 'Tenant not found' }, 404);
    }

    if (!idpStorage) {
      return c.json({ error: 'not_implemented', message: 'Identity provider storage not configured' }, 501);
    }

    try {
      const provider = await idpStorage.create({
        tenantId,
        ...input,
      });
      return c.json(provider, 201);
    } catch (error) {
      if (error instanceof Error && error.message.includes('unique')) {
        return c.json({ error: 'conflict', message: 'Identity provider with this slug already exists' }, 409);
      }
      throw error;
    }
  });

  // Get identity provider by ID
  app.get('/identity-providers/:id', async (c) => {
    const id = c.req.param('id');
    const idpStorage = getIdpStorage();

    if (!idpStorage) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    const provider = await idpStorage.findById(id);
    if (!provider) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    return c.json(provider);
  });

  // Update identity provider
  app.put('/identity-providers/:id', zValidator('json', updateIdentityProviderSchema), async (c) => {
    const id = c.req.param('id');
    const input = c.req.valid('json');
    const idpStorage = getIdpStorage();

    if (!idpStorage) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    const existing = await idpStorage.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    const provider = await idpStorage.update(id, input);
    return c.json(provider);
  });

  // Delete identity provider
  app.delete('/identity-providers/:id', async (c) => {
    const id = c.req.param('id');
    const idpStorage = getIdpStorage();

    if (!idpStorage) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    const existing = await idpStorage.findById(id);
    if (!existing) {
      return c.json({ error: 'not_found', message: 'Identity provider not found' }, 404);
    }

    await idpStorage.delete(id);
    return c.body(null, 204);
  });

  return app;
}
