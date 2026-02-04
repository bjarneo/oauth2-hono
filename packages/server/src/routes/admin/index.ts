import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import { adminAuth, type AdminAuthOptions } from './middleware.js';
import { createTenantRoutes } from './tenants.js';
import { createClientRoutes } from './clients.js';
import { createSigningKeyRoutes } from './signing-keys.js';
import { createTokenRoutes } from './tokens.js';
import { createStatsRoutes } from './stats.js';
import { createIdentityProviderRoutes } from './identity-providers.js';

export interface AdminRoutesOptions {
  storage: IStorage;
  auth?: AdminAuthOptions;
}

/**
 * Create the admin API routes
 * Mount at /_admin prefix
 */
export function createAdminRoutes(options: AdminRoutesOptions) {
  const { storage, auth } = options;
  const app = new Hono<{ Variables: OAuthVariables }>();

  // Apply authentication middleware
  app.use('*', adminAuth(auth));

  // Stats routes
  app.route('/stats', createStatsRoutes({ storage }));

  // Tenant routes
  app.route('/tenants', createTenantRoutes({ storage }));

  // Client routes (nested tenant routes and standalone)
  const clientRoutes = createClientRoutes({ storage });
  app.route('/', clientRoutes);

  // Signing key routes
  const signingKeyRoutes = createSigningKeyRoutes({ storage });
  app.route('/', signingKeyRoutes);

  // Token routes
  const tokenRoutes = createTokenRoutes({ storage });
  app.route('/', tokenRoutes);

  // Identity provider routes
  const idpRoutes = createIdentityProviderRoutes({ storage });
  app.route('/', idpRoutes);

  return app;
}

export { adminAuth } from './middleware.js';
export type { AdminAuthOptions } from './middleware.js';
