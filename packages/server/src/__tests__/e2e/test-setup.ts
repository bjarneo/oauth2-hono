import * as jose from 'jose';
import { createOAuth2Server, type OAuth2ServerOptions } from '../../app.js';
import { createMemoryStorage } from '../../storage/memory/index.js';
import type { IStorage, IUserAuthenticator, AuthenticationResult } from '../../storage/interfaces/index.js';
import type { Context } from 'hono';
import { generateCodeChallenge } from '../../crypto/pkce.js';
import { generateRandomBase64Url } from '../../crypto/random.js';

/**
 * Test fixtures and helpers
 */

// Test user authenticator that auto-authenticates
export class TestUserAuthenticator implements IUserAuthenticator {
  private consents = new Map<string, string[]>();
  private currentUser = {
    id: 'test-user-001',
    username: 'testuser',
    email: 'test@example.com',
    emailVerified: true,
    name: 'Test User',
  };

  setCurrentUser(user: { id: string; username?: string; email?: string; name?: string }) {
    this.currentUser = { ...this.currentUser, ...user };
  }

  async authenticate(_ctx: Context): Promise<AuthenticationResult> {
    return {
      authenticated: true,
      user: this.currentUser,
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
    if (userId === this.currentUser.id) {
      return this.currentUser;
    }
    return {
      id: userId,
      username: `user-${userId}`,
      email: `${userId}@example.com`,
    };
  }
}

// Generate a valid PKCE code verifier (43-128 characters using unreserved characters)
export function generateCodeVerifier(): string {
  // Base64url uses only unreserved characters (A-Za-z0-9-_)
  // 48 bytes = 64 base64url characters
  return generateRandomBase64Url(48);
}

// Create Basic auth header
export function basicAuth(clientId: string, clientSecret: string): string {
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  return `Basic ${credentials}`;
}

// Re-export for convenience
export { generateCodeChallenge, generateRandomBase64Url, jose };

// Type helpers for test responses
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface ErrorResponse {
  error: string;
  error_description?: string;
}

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface JWKSResponse {
  keys: Array<{
    kty: string;
    kid: string;
    use: string;
    alg?: string;
    n?: string;
    e?: string;
  }>;
}

export interface OpenIDConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  registration_endpoint?: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported: string[];
  code_challenge_methods_supported?: string[];
  claims_supported?: string[];
  claims_parameter_supported?: boolean;
  backchannel_logout_supported?: boolean;
  backchannel_logout_session_supported?: boolean;
  frontchannel_logout_supported?: boolean;
  frontchannel_logout_session_supported?: boolean;
}

// Shared test context
export interface TestContext {
  storage: IStorage;
  userAuthenticator: TestUserAuthenticator;
  app: ReturnType<typeof createOAuth2Server>;
  tenantSlug: string;
  tenantId: string;
  confidentialClientId: string;
  confidentialClientSecret: string;
  publicClientId: string;
}

// Setup function for tests
export async function setupTestContext(): Promise<TestContext> {
  const storage = createMemoryStorage();
  const userAuthenticator = new TestUserAuthenticator();

  // Create test tenant with extended allowed scopes
  const tenant = await storage.tenants.create({
    name: 'Test Tenant',
    slug: 'test',
    issuer: 'http://localhost:3000/test',
    allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
  });

  // Create signing key
  await storage.signingKeys.create({
    tenantId: tenant.id,
    algorithm: 'RS256',
    isPrimary: true,
  });

  // Create confidential client
  const { client: confidentialClient, clientSecret } = await storage.clients.create({
    tenantId: tenant.id,
    clientType: 'confidential',
    authMethod: 'client_secret_basic',
    name: 'Test Confidential Client',
    redirectUris: ['http://localhost:3001/callback'],
    allowedGrants: ['authorization_code', 'client_credentials', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
    defaultScopes: ['openid', 'profile'],
  });

  // Create public client
  const { client: publicClient } = await storage.clients.create({
    tenantId: tenant.id,
    clientType: 'public',
    authMethod: 'none',
    name: 'Test Public Client',
    redirectUris: ['http://localhost:3001/callback'],
    allowedGrants: ['authorization_code', 'refresh_token'],
    allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
    defaultScopes: ['openid', 'profile'],
  });

  // Create OAuth2 server with high rate limits for testing
  const options: OAuth2ServerOptions = {
    storage,
    userAuthenticator,
    baseUrl: 'http://localhost:3000',
    enableLogging: false,
    rateLimit: {
      windowMs: 60000,
      maxRequests: 1000, // High limit for tests
    },
  };
  const app = createOAuth2Server(options);

  return {
    storage,
    userAuthenticator,
    app,
    tenantSlug: tenant.slug,
    tenantId: tenant.id,
    confidentialClientId: confidentialClient.clientId,
    confidentialClientSecret: clientSecret!,
    publicClientId: publicClient.clientId,
  };
}

// Helper to reset user for each test
export function resetUser(userAuthenticator: TestUserAuthenticator) {
  userAuthenticator.setCurrentUser({
    id: 'test-user-001',
    username: 'testuser',
    email: 'test@example.com',
    name: 'Test User',
  });
}
