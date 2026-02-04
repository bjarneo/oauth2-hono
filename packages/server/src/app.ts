import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { OAuthVariables } from './types/hono.js';
import type { IStorage, IUserAuthenticator } from './storage/interfaces/index.js';
import { tenantResolver } from './middleware/tenant-resolver.js';
import { oauthErrorHandler, securityHeaders, requestLogger } from './middleware/error-handler.js';
import { rateLimiter } from './middleware/rate-limiter.js';
import {
  createAuthorizeRoutes,
  createTokenRoutes,
  createRevokeRoutes,
  createIntrospectRoutes,
  createDeviceAuthorizationRoutes,
  createUserInfoRoutes,
  createEndSessionRoutes,
  createRegisterRoutes,
} from './routes/oauth/index.js';
import { createOpenIDConfigurationRoutes, createJWKSRoutes } from './routes/discovery/index.js';
import { createAdminRoutes, type AdminAuthOptions } from './routes/admin/index.js';
import { createFederationRoutes, type FederationRoutesOptions } from './routes/federation/index.js';

export interface OAuth2ServerOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  baseUrl?: string;
  verificationUri?: string;
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
  enableCors?: boolean;
  enableLogging?: boolean;
  /**
   * Allow open client registration without authentication
   */
  allowOpenRegistration?: boolean;
  /**
   * Initial access token for client registration
   */
  registrationAccessToken?: string;
  /**
   * Callback for logout events
   */
  onLogout?: (tenantId: string, userId: string, clientId?: string) => Promise<void>;
  /**
   * Admin API configuration
   */
  admin?: {
    enabled?: boolean;
    auth?: AdminAuthOptions;
  };
  /**
   * Federation configuration for external identity providers
   */
  federation?: {
    enabled?: boolean;
    onFederatedLogin?: FederationRoutesOptions['onFederatedLogin'];
  };
}

/**
 * Create the OAuth 2.0 Authorization Server application
 */
export function createOAuth2Server(options: OAuth2ServerOptions): Hono<{ Variables: OAuthVariables }> {
  const {
    storage,
    userAuthenticator,
    baseUrl = 'http://localhost:3000',
    verificationUri,
    rateLimit = { windowMs: 60000, maxRequests: 100 },
    enableCors = true,
    enableLogging = true,
    allowOpenRegistration = false,
    registrationAccessToken,
    onLogout,
    admin = { enabled: true },
    federation = { enabled: true },
  } = options;

  const app = new Hono<{ Variables: OAuthVariables }>();

  // Global error handler
  app.onError(oauthErrorHandler);

  // Security headers
  app.use('*', securityHeaders());

  // Logging
  if (enableLogging) {
    app.use('*', requestLogger());
  }

  // CORS (needed for token endpoint from SPAs)
  if (enableCors) {
    app.use(
      '*',
      cors({
        origin: '*',
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Authorization', 'Content-Type'],
        exposeHeaders: ['WWW-Authenticate'],
        maxAge: 86400,
      })
    );
  }

  // Rate limiting
  app.use('*', rateLimiter(rateLimit));

  // Health check (before tenant resolution)
  app.get('/health', (c) => c.json({ status: 'ok' }));

  // Admin API routes
  if (admin.enabled !== false) {
    app.route('/_admin', createAdminRoutes({ storage, auth: admin.auth }));
  }

  // Create tenant-scoped routes
  const tenantRoutes = new Hono<{ Variables: OAuthVariables }>();

  // Tenant resolution middleware
  tenantRoutes.use(
    '*',
    tenantResolver({
      tenantStorage: storage.tenants,
      signingKeyStorage: storage.signingKeys,
    })
  );

  // OAuth endpoints
  if (userAuthenticator) {
    tenantRoutes.route(
      '/authorize',
      createAuthorizeRoutes({ storage, userAuthenticator })
    );
  }

  tenantRoutes.route(
    '/token',
    createTokenRoutes({
      storage,
      userAuthenticator,
      tokenEndpointUrl: `${baseUrl}/:tenant/token`,
    })
  );

  tenantRoutes.route('/revoke', createRevokeRoutes({ storage }));

  tenantRoutes.route(
    '/introspect',
    createIntrospectRoutes({ storage, userAuthenticator })
  );

  tenantRoutes.route(
    '/device_authorization',
    createDeviceAuthorizationRoutes({
      storage,
      verificationUri: verificationUri ?? `${baseUrl}/:tenant/device`,
    })
  );

  // UserInfo endpoint
  tenantRoutes.route(
    '/userinfo',
    createUserInfoRoutes({
      signingKeyStorage: storage.signingKeys,
      userAuthenticator,
    })
  );

  // End Session (Logout) endpoint
  tenantRoutes.route(
    '/end_session',
    createEndSessionRoutes({
      storage,
      userAuthenticator,
      onLogout,
    })
  );

  // Dynamic Client Registration endpoint
  tenantRoutes.route(
    '/register',
    createRegisterRoutes({
      storage,
      baseUrl,
      allowOpenRegistration,
      initialAccessToken: registrationAccessToken,
    })
  );

  // Discovery endpoints
  tenantRoutes.route(
    '/.well-known/openid-configuration',
    createOpenIDConfigurationRoutes()
  );

  tenantRoutes.route(
    '/.well-known/jwks.json',
    createJWKSRoutes({ signingKeyStorage: storage.signingKeys })
  );

  // Federation routes for external identity providers
  if (federation.enabled !== false && storage.identityProviders) {
    tenantRoutes.route(
      '/federate',
      createFederationRoutes({
        storage,
        userAuthenticator,
        baseUrl,
        onFederatedLogin: federation.onFederatedLogin,
      })
    );
  }

  // Mount tenant routes at /:tenant
  app.route('/:tenant', tenantRoutes);

  return app;
}
