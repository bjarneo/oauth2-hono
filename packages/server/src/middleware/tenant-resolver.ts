import type { MiddlewareHandler } from 'hono';
import type { OAuthVariables } from '../types/hono.js';
import type { ITenantStorage, ISigningKeyStorage } from '../storage/interfaces/index.js';
import { OAuthError } from '../errors/oauth-error.js';

export interface TenantResolverOptions {
  tenantStorage: ITenantStorage;
  signingKeyStorage: ISigningKeyStorage;
  paramName?: string; // URL parameter name for tenant slug, default 'tenant'
}

/**
 * Middleware to resolve tenant from URL path parameter
 *
 * Expected URL format: /:tenant/token, /:tenant/authorize, etc.
 *
 * Sets `tenant` and `signingKey` in context variables
 */
export function tenantResolver(options: TenantResolverOptions): MiddlewareHandler<{
  Variables: OAuthVariables;
}> {
  const { tenantStorage, signingKeyStorage, paramName = 'tenant' } = options;

  return async (c, next) => {
    const tenantSlug = c.req.param(paramName);

    if (!tenantSlug) {
      throw OAuthError.invalidRequest('Missing tenant identifier');
    }

    // Look up tenant by slug
    const tenant = await tenantStorage.findBySlug(tenantSlug);

    if (!tenant) {
      throw OAuthError.invalidRequest(`Unknown tenant: ${tenantSlug}`);
    }

    // Get the primary signing key for this tenant
    let signingKey = await signingKeyStorage.getPrimary(tenant.id);

    // If no signing key exists, create one
    if (!signingKey) {
      signingKey = await signingKeyStorage.create({
        tenantId: tenant.id,
        algorithm: 'RS256',
        isPrimary: true,
      });
    }

    // Set tenant and signing key in context
    c.set('tenant', tenant);
    c.set('signingKey', signingKey);

    await next();
  };
}
