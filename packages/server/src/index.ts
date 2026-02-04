import { serve } from '@hono/node-server';
import { createOAuth2Server } from './app.js';
import { createMemoryStorage } from './storage/memory/index.js';
import { createPrismaStorage } from './storage/prisma/index.js';
import { getConfig } from './config/index.js';
import type { IUserAuthenticator, AuthenticationResult } from './storage/interfaces/user-storage.js';
import type { IStorage } from './storage/interfaces/index.js';
import type { Context } from 'hono';

// Load configuration
const config = getConfig();

/**
 * Example user authenticator for development/testing
 * In production, implement your own authenticator that integrates with your user system
 */
class DevelopmentUserAuthenticator implements IUserAuthenticator {
  private consents = new Map<string, string[]>();

  async authenticate(ctx: Context): Promise<AuthenticationResult> {
    // For development, check for a user_id header or query param
    const userId =
      ctx.req.query('user_id') ??
      ctx.req.header('X-User-Id') ??
      null;

    if (!userId) {
      // In development, auto login as test user
      // In production, redirect to your login page
      return {
        authenticated: true,
        user: {
          id: 'test-user-001',
          username: 'testuser',
          email: 'test@example.com',
          emailVerified: true,
          name: 'Test User',
        },
      };
    }

    return {
      authenticated: true,
      user: {
        id: userId,
        username: `user-${userId}`,
        email: `${userId}@example.com`,
      },
    };
  }

  async getConsent(tenantId: string, userId: string, clientId: string): Promise<string[] | null> {
    const key = `${tenantId}:${userId}:${clientId}`;
    return this.consents.get(key) ?? null;
  }

  async saveConsent(tenantId: string, userId: string, clientId: string, scopes: string[]): Promise<void> {
    const key = `${tenantId}:${userId}:${clientId}`;
    this.consents.set(key, scopes);
  }

  async revokeConsent(tenantId: string, userId: string, clientId: string): Promise<void> {
    const key = `${tenantId}:${userId}:${clientId}`;
    this.consents.delete(key);
  }

  async getUserById(_tenantId: string, userId: string) {
    return {
      id: userId,
      username: `user-${userId}`,
      email: `${userId}@example.com`,
    };
  }
}

// Create storage based on environment
let storage: IStorage;

if (config.database.url) {
  console.log('Using Prisma storage with PostgreSQL');
  storage = createPrismaStorage();
} else {
  console.log('Using in-memory storage (no DATABASE_URL configured)');
  storage = createMemoryStorage();
}

// Create OAuth server
const userAuthenticator = new DevelopmentUserAuthenticator();

const app = createOAuth2Server({
  storage,
  userAuthenticator,
  baseUrl: `http://${config.server.host === '0.0.0.0' ? 'localhost' : config.server.host}:${config.server.port}`,
  rateLimit: config.rateLimit,
  enableLogging: config.server.nodeEnv !== 'test',
});

// Start server
serve(
  {
    fetch: app.fetch,
    port: config.server.port,
    hostname: config.server.host,
  },
  (info) => {
    console.log(`OAuth 2.0 Authorization Server running at http://${info.address}:${info.port}`);
    console.log('');
    console.log('Endpoints:');
    console.log(`  Discovery: http://localhost:${info.port}/<tenant>/.well-known/openid-configuration`);
    console.log(`  Authorize: http://localhost:${info.port}/<tenant>/authorize`);
    console.log(`  Token:     http://localhost:${info.port}/<tenant>/token`);
    console.log(`  JWKS:      http://localhost:${info.port}/<tenant>/.well-known/jwks.json`);
    console.log('');
    if (!config.database.url) {
      console.log('Note: Running with in-memory storage. Data will be lost on restart.');
      console.log('      Set DATABASE_URL and run "npm run db:push && npm run db:seed" for persistence.');
    }
  }
);

// Export for programmatic use
export { createOAuth2Server } from './app.js';
export { createMemoryStorage } from './storage/memory/index.js';
export { createPrismaStorage, closePrisma } from './storage/prisma/index.js';
export * from './types/index.js';
export * from './storage/interfaces/index.js';
export * from './config/index.js';
export * from './errors/index.js';
export * from './crypto/index.js';
