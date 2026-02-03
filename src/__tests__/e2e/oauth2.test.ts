import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { Hono } from 'hono';
import * as jose from 'jose';
import { createOAuth2Server, type OAuth2ServerOptions } from '../../app.js';
import { createMemoryStorage } from '../../storage/memory/index.js';
import type { IStorage, IUserAuthenticator, AuthenticationResult } from '../../storage/interfaces/index.js';
import type { OAuthVariables } from '../../types/hono.js';
import type { Context } from 'hono';
import { generateCodeChallenge } from '../../crypto/pkce.js';
import { generateRandomBase64Url } from '../../crypto/random.js';
import { bearerAuth } from '../../middleware/bearer-auth.js';
import { tenantResolver } from '../../middleware/tenant-resolver.js';
import { decodeJwt, getJwtHeader } from '../../crypto/jwt.js';
import type { AccessTokenPayload, IdTokenPayload } from '../../types/token.js';

/**
 * Test fixtures and helpers
 */

// Test user authenticator that auto-authenticates
class TestUserAuthenticator implements IUserAuthenticator {
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
function generateCodeVerifier(): string {
  // Base64url uses only unreserved characters (A-Za-z0-9-_)
  // 48 bytes = 64 base64url characters
  return generateRandomBase64Url(48);
}

// Create Basic auth header
function basicAuth(clientId: string, clientSecret: string): string {
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  return `Basic ${credentials}`;
}

describe('OAuth2 E2E Tests', () => {
  let storage: IStorage;
  let userAuthenticator: TestUserAuthenticator;
  let app: ReturnType<typeof createOAuth2Server>;

  // Test data
  let tenantSlug: string;
  let tenantId: string;
  let confidentialClientId: string;
  let confidentialClientSecret: string;
  let publicClientId: string;

  beforeAll(async () => {
    // Initialize storage and authenticator
    storage = createMemoryStorage();
    userAuthenticator = new TestUserAuthenticator();

    // Create test tenant with extended allowed scopes
    const tenant = await storage.tenants.create({
      name: 'Test Tenant',
      slug: 'test',
      issuer: 'http://localhost:3000/test',
      allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
    });
    tenantSlug = tenant.slug;
    tenantId = tenant.id;

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
    confidentialClientId = confidentialClient.clientId;
    confidentialClientSecret = clientSecret!;

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
    publicClientId = publicClient.clientId;

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
    app = createOAuth2Server(options);
  });

  beforeEach(() => {
    // Reset user for each test
    userAuthenticator.setCurrentUser({
      id: 'test-user-001',
      username: 'testuser',
      email: 'test@example.com',
      name: 'Test User',
    });
  });

  // ==========================================================================
  // Health Check
  // ==========================================================================
  describe('Health Check', () => {
    it('should return OK status', async () => {
      const res = await app.request('/health');
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ status: 'ok' });
    });
  });

  // ==========================================================================
  // Discovery Endpoints
  // ==========================================================================
  describe('Discovery Endpoints', () => {
    describe('OpenID Configuration', () => {
      it('should return valid OpenID configuration', async () => {
        const res = await app.request(`/${tenantSlug}/.well-known/openid-configuration`);
        expect(res.status).toBe(200);

        const config = await res.json();
        expect(config.issuer).toBe('http://localhost:3000/test');
        expect(config.authorization_endpoint).toBe('http://localhost:3000/test/authorize');
        expect(config.token_endpoint).toBe('http://localhost:3000/test/token');
        expect(config.revocation_endpoint).toBe('http://localhost:3000/test/revoke');
        expect(config.introspection_endpoint).toBe('http://localhost:3000/test/introspect');
        expect(config.jwks_uri).toBe('http://localhost:3000/test/.well-known/jwks.json');
        expect(config.response_types_supported).toContain('code');
        expect(config.grant_types_supported).toBeDefined();
        expect(config.code_challenge_methods_supported).toContain('S256');
      });

      it('should return error for unknown tenant', async () => {
        const res = await app.request('/unknown-tenant/.well-known/openid-configuration');
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toBe('invalid_request');
      });
    });

    describe('JWKS', () => {
      it('should return valid JWKS', async () => {
        const res = await app.request(`/${tenantSlug}/.well-known/jwks.json`);
        expect(res.status).toBe(200);

        const jwks = await res.json();
        expect(jwks.keys).toBeDefined();
        expect(Array.isArray(jwks.keys)).toBe(true);
        expect(jwks.keys.length).toBeGreaterThan(0);

        const key = jwks.keys[0];
        expect(key.kty).toBe('RSA');
        expect(key.kid).toBeDefined();
        expect(key.use).toBe('sig');
        expect(key.n).toBeDefined();
        expect(key.e).toBeDefined();
      });
    });
  });

  // ==========================================================================
  // Client Credentials Grant
  // ==========================================================================
  describe('Client Credentials Grant', () => {
    it('should issue access token for valid credentials', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read api:write',
        }),
      });

      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.access_token).toBeDefined();
      expect(body.token_type).toBe('Bearer');
      expect(body.expires_in).toBeDefined();
      expect(body.refresh_token).toBeUndefined(); // No refresh token for client credentials
    });

    it('should reject invalid client credentials', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, 'wrong-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('invalid_client');
    });

    it('should reject public clients', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: publicClientId,
        }),
      });

      expect(res.status).toBe(401);
    });

    it('should reject missing grant_type', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({}),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_request');
    });

    it('should reject unsupported grant type', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'password', // Not supported
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('unsupported_grant_type');
    });
  });

  // ==========================================================================
  // Authorization Code Grant (with PKCE)
  // ==========================================================================
  describe('Authorization Code Grant', () => {
    it('should complete full authorization code flow with PKCE', async () => {
      // Step 1: Generate PKCE values
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const state = 'random-state-value';

      // Pre-save consent for the user to skip consent screen (include offline_access for refresh token)
      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile', 'email', 'offline_access']
      );

      // Step 2: Authorization request (include offline_access to get refresh token)
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile email offline_access');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Should redirect with authorization code
      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      expect(location).toBeDefined();

      const redirectUrl = new URL(location!);
      expect(redirectUrl.origin).toBe('http://localhost:3001');
      expect(redirectUrl.pathname).toBe('/callback');
      expect(redirectUrl.searchParams.get('state')).toBe(state);
      expect(redirectUrl.searchParams.get('iss')).toBe('http://localhost:3000/test');

      const code = redirectUrl.searchParams.get('code');
      expect(code).toBeDefined();

      // Step 3: Token exchange
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes.status).toBe(200);

      const tokens = await tokenRes.json();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.token_type).toBe('Bearer');
      expect(tokens.expires_in).toBeDefined();
      expect(tokens.refresh_token).toBeDefined(); // Should have refresh token
    });

    it('should work with public client and PKCE', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const state = 'public-client-state';

      // Pre-save consent
      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        publicClientId,
        ['openid', 'profile']
      );

      // Authorization request
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', publicClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      expect(authRes.status).toBe(302);

      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      const code = redirectUrl.searchParams.get('code');

      // Token exchange without client secret (public client)
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: publicClientId,
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json();
      expect(tokens.access_token).toBeDefined();
    });

    it('should reject authorization without PKCE', async () => {
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      // Missing code_challenge

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Should redirect with error
      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toContain('code_challenge');
    });

    it('should reject invalid code_verifier', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Pre-save consent
      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      // Get authorization code
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const location = authRes.headers.get('Location');
      const code = new URL(location!).searchParams.get('code');

      // Try to exchange with wrong verifier
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: 'wrong-verifier-that-does-not-match-the-challenge',
        }),
      });

      expect(tokenRes.status).toBe(400);
      const body = await tokenRes.json();
      expect(body.error).toBe('invalid_grant');
    });

    it('should reject invalid redirect_uri', async () => {
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://malicious.com/callback');
      authUrl.searchParams.set('code_challenge', 'abc123');
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Should return error directly (not redirect)
      expect(authRes.status).toBe(400);
      const body = await authRes.json();
      expect(body.error).toBe('invalid_request');
    });

    it('should reject reused authorization code', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      // Get authorization code
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const location = authRes.headers.get('Location');
      const code = new URL(location!).searchParams.get('code');

      // First token exchange (should succeed)
      const tokenRes1 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });
      expect(tokenRes1.status).toBe(200);

      // Second token exchange (should fail - code already used)
      const tokenRes2 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes2.status).toBe(400);
      const body = await tokenRes2.json();
      expect(body.error).toBe('invalid_grant');
    });
  });

  // ==========================================================================
  // Refresh Token Grant
  // ==========================================================================
  describe('Refresh Token Grant', () => {
    let refreshToken: string;

    beforeEach(async () => {
      // Get a refresh token via authorization code flow
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile', 'offline_access']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile offline_access');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      const tokens = await tokenRes.json();
      refreshToken = tokens.refresh_token;
    });

    it('should issue new tokens with valid refresh token', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      });

      expect(res.status).toBe(200);

      const tokens = await res.json();
      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.refresh_token).not.toBe(refreshToken); // Should be rotated
    });

    it('should allow scope downgrading', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'openid profile', // Subset of original scopes
        }),
      });

      expect(res.status).toBe(200);
      const tokens = await res.json();
      expect(tokens.scope).toBe('openid profile');
    });

    it('should reject scope upgrading', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'openid profile email api:read', // api:read wasn't in original
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_scope');
    });

    it('should reject reused refresh token (rotation detection)', async () => {
      // First refresh (should succeed and rotate)
      const res1 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      });
      expect(res1.status).toBe(200);

      // Try to reuse original refresh token (should fail - already revoked)
      const res2 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      });

      expect(res2.status).toBe(400);
      const body = await res2.json();
      expect(body.error).toBe('invalid_grant');
    });

    it('should reject invalid refresh token', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: 'invalid-refresh-token',
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_grant');
    });
  });

  // ==========================================================================
  // Device Code Grant
  // ==========================================================================
  describe('Device Code Grant', () => {
    it('should issue device code', async () => {
      const res = await app.request(`/${tenantSlug}/device_authorization`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: confidentialClientId,
          scope: 'openid profile',
        }),
      });

      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.device_code).toBeDefined();
      expect(body.user_code).toBeDefined();
      expect(body.verification_uri).toBeDefined();
      expect(body.verification_uri_complete).toBeDefined();
      expect(body.expires_in).toBeDefined();
      expect(body.interval).toBeDefined();
    });

    it('should return authorization_pending while waiting', async () => {
      // Get device code
      const deviceRes = await app.request(`/${tenantSlug}/device_authorization`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: confidentialClientId,
          scope: 'openid profile',
        }),
      });

      const { device_code } = await deviceRes.json();

      // Poll for token (should be pending)
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        }),
      });

      expect(tokenRes.status).toBe(400);
      const body = await tokenRes.json();
      expect(body.error).toBe('authorization_pending');
    });

    it('should issue tokens after user authorization', async () => {
      // Get device code
      const deviceRes = await app.request(`/${tenantSlug}/device_authorization`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: confidentialClientId,
          scope: 'openid profile',
        }),
      });

      const { device_code } = await deviceRes.json();

      // Simulate user authorization (directly in storage)
      // In real scenario, user would visit verification_uri
      const deviceCodeRecord = await storage.deviceCodes.findByValue(tenantId, device_code);
      if (deviceCodeRecord) {
        await storage.deviceCodes.authorize(deviceCodeRecord.id, 'test-user-001');
      }

      // Poll for token (should succeed now)
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json();
      expect(tokens.access_token).toBeDefined();
    });

    it('should reject if user denies authorization', async () => {
      // Get device code
      const deviceRes = await app.request(`/${tenantSlug}/device_authorization`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: confidentialClientId,
          scope: 'openid profile',
        }),
      });

      const { device_code } = await deviceRes.json();

      // Simulate user denial
      const deviceCodeRecord = await storage.deviceCodes.findByValue(tenantId, device_code);
      if (deviceCodeRecord) {
        await storage.deviceCodes.deny(deviceCodeRecord.id);
      }

      // Poll for token (should fail)
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        }),
      });

      // access_denied returns 403 per RFC
      expect(tokenRes.status).toBe(403);
      const body = await tokenRes.json();
      expect(body.error).toBe('access_denied');
    });
  });

  // ==========================================================================
  // Token Introspection
  // ==========================================================================
  describe('Token Introspection', () => {
    let accessToken: string;

    beforeEach(async () => {
      // Get an access token
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read',
        }),
      });

      const tokens = await res.json();
      accessToken = tokens.access_token;
    });

    it('should return active=true for valid token', async () => {
      const res = await app.request(`/${tenantSlug}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: accessToken,
        }),
      });

      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.active).toBe(true);
      expect(body.client_id).toBe(confidentialClientId);
      expect(body.token_type).toBe('Bearer');
      expect(body.exp).toBeDefined();
    });

    it('should return active=false for invalid token', async () => {
      const res = await app.request(`/${tenantSlug}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: 'invalid-token',
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.active).toBe(false);
    });

    it('should require client authentication', async () => {
      const res = await app.request(`/${tenantSlug}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: accessToken,
        }),
      });

      expect(res.status).toBe(401);
    });

    it('should return active=false for revoked token', async () => {
      // Revoke the token first
      await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: accessToken,
          token_type_hint: 'access_token',
        }),
      });

      // Introspect revoked token
      const res = await app.request(`/${tenantSlug}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: accessToken,
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.active).toBe(false);
    });
  });

  // ==========================================================================
  // Token Revocation
  // ==========================================================================
  describe('Token Revocation', () => {
    it('should revoke access token', async () => {
      // Get token
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      const { access_token } = await tokenRes.json();

      // Revoke token
      const revokeRes = await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: access_token,
          token_type_hint: 'access_token',
        }),
      });

      // RFC 7009: Always returns 200 OK
      expect(revokeRes.status).toBe(200);
    });

    it('should revoke refresh token', async () => {
      // Get refresh token via auth code flow
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile', 'offline_access']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile offline_access');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      const { refresh_token } = await tokenRes.json();

      // Revoke refresh token
      const revokeRes = await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: refresh_token,
          token_type_hint: 'refresh_token',
        }),
      });

      expect(revokeRes.status).toBe(200);

      // Try to use revoked refresh token
      const refreshRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token,
        }),
      });

      expect(refreshRes.status).toBe(400);
      const body = await refreshRes.json();
      expect(body.error).toBe('invalid_grant');
    });

    it('should return 200 even for invalid token (RFC 7009)', async () => {
      const res = await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: 'completely-invalid-token',
        }),
      });

      // RFC 7009 requires always returning 200 to prevent token fishing
      expect(res.status).toBe(200);
    });

    it('should require token parameter', async () => {
      const res = await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({}),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_request');
    });
  });

  // ==========================================================================
  // Error Handling
  // ==========================================================================
  describe('Error Handling', () => {
    it('should return proper error format', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'invalid_grant_type',
        }),
      });

      const body = await res.json();
      expect(body.error).toBeDefined();
      // error_description is optional but helpful
    });

    it('should handle unknown tenant gracefully', async () => {
      const res = await app.request('/nonexistent/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_request');
    });

    it('should include security headers', async () => {
      const res = await app.request('/health');

      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    });
  });

  // ==========================================================================
  // Multi-tenant Isolation
  // ==========================================================================
  describe('Multi-tenant Isolation', () => {
    let otherTenantSlug: string;
    let otherClientId: string;
    let otherClientSecret: string;

    beforeAll(async () => {
      // Create another tenant
      const tenant = await storage.tenants.create({
        name: 'Other Tenant',
        slug: 'other',
        issuer: 'http://localhost:3000/other',
      });
      otherTenantSlug = tenant.slug;

      await storage.signingKeys.create({
        tenantId: tenant.id,
        algorithm: 'RS256',
        isPrimary: true,
      });

      const { client, clientSecret } = await storage.clients.create({
        tenantId: tenant.id,
        clientType: 'confidential',
        authMethod: 'client_secret_basic',
        name: 'Other Client',
        redirectUris: ['http://localhost:3001/callback'],
        allowedGrants: ['client_credentials'],
        allowedScopes: ['api:read'],
      });
      otherClientId = client.clientId;
      otherClientSecret = clientSecret!;
    });

    it('should not allow cross-tenant client usage', async () => {
      // Try to use other tenant's client on first tenant
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(otherClientId, otherClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('invalid_client');
    });

    it('should work correctly for each tenant', async () => {
      // First tenant
      const res1 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });
      expect(res1.status).toBe(200);

      // Other tenant
      const res2 = await app.request(`/${otherTenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(otherClientId, otherClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });
      expect(res2.status).toBe(200);
    });
  });

  // ==========================================================================
  // Client Authentication Methods (Extended)
  // ==========================================================================
  describe('Client Authentication Methods', () => {
    let postAuthClientId: string;
    let postAuthClientSecret: string;
    let jwtAuthClientId: string;
    let jwtClientKeyPair: { publicKey: jose.KeyLike; privateKey: jose.KeyLike };
    let jwtClientJwk: jose.JWK;

    beforeAll(async () => {
      // Create client with client_secret_post auth
      const { client: postClient, clientSecret } = await storage.clients.create({
        tenantId: tenantId,
        clientType: 'confidential',
        authMethod: 'client_secret_post',
        name: 'POST Auth Client',
        redirectUris: ['http://localhost:3001/callback'],
        allowedGrants: ['client_credentials'],
        allowedScopes: ['api:read'],
      });
      postAuthClientId = postClient.clientId;
      postAuthClientSecret = clientSecret!;

      // Generate key pair for private_key_jwt client
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
      jwtClientKeyPair = { publicKey, privateKey };
      jwtClientJwk = await jose.exportJWK(publicKey);
      jwtClientJwk.kid = 'test-key-1';
      jwtClientJwk.alg = 'RS256';
      jwtClientJwk.use = 'sig';

      // Create client with private_key_jwt auth
      const { client: jwtClient } = await storage.clients.create({
        tenantId: tenantId,
        clientType: 'confidential',
        authMethod: 'private_key_jwt',
        name: 'JWT Auth Client',
        redirectUris: ['http://localhost:3001/callback'],
        allowedGrants: ['client_credentials'],
        allowedScopes: ['api:read'],
        jwks: { keys: [jwtClientJwk as jose.JWK & { kid: string }] },
      });
      jwtAuthClientId = jwtClient.clientId;
    });

    describe('client_secret_post', () => {
      it('should authenticate with credentials in POST body', async () => {
        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: postAuthClientId,
            client_secret: postAuthClientSecret,
          }),
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.access_token).toBeDefined();
      });

      it('should reject wrong auth method (Basic instead of POST)', async () => {
        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': basicAuth(postAuthClientId, postAuthClientSecret),
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
          }),
        });

        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.error).toBe('invalid_client');
      });

      it('should reject invalid secret in POST body', async () => {
        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: postAuthClientId,
            client_secret: 'wrong-secret',
          }),
        });

        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.error).toBe('invalid_client');
      });
    });

    describe('private_key_jwt', () => {
      it('should authenticate with JWT assertion', async () => {
        // Create client assertion JWT
        const now = Math.floor(Date.now() / 1000);
        const assertion = await new jose.SignJWT({
          iss: jwtAuthClientId,
          sub: jwtAuthClientId,
          aud: 'http://localhost:3000/:tenant/token',
          iat: now,
          exp: now + 300,
          jti: generateRandomBase64Url(16),
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
          .sign(jwtClientKeyPair.privateKey);

        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: jwtAuthClientId,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: assertion,
          }),
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.access_token).toBeDefined();
      });

      it('should reject invalid JWT assertion', async () => {
        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: jwtAuthClientId,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: 'invalid.jwt.assertion',
          }),
        });

        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.error).toBe('invalid_client');
      });

      it('should reject JWT signed with wrong key', async () => {
        // Generate a different key pair
        const { privateKey: wrongKey } = await jose.generateKeyPair('RS256');

        const now = Math.floor(Date.now() / 1000);
        const assertion = await new jose.SignJWT({
          iss: jwtAuthClientId,
          sub: jwtAuthClientId,
          aud: 'http://localhost:3000/:tenant/token',
          iat: now,
          exp: now + 300,
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
          .sign(wrongKey);

        const res = await app.request(`/${tenantSlug}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: jwtAuthClientId,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: assertion,
          }),
        });

        expect(res.status).toBe(401);
      });
    });
  });

  // ==========================================================================
  // ID Token Validation
  // ==========================================================================
  describe('ID Token Validation', () => {
    it('should return valid ID token with openid scope', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const nonce = generateRandomBase64Url(16);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile', 'email']
      );

      // Authorization request with nonce
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      authUrl.searchParams.set('nonce', nonce);

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      // Token exchange
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json();
      expect(tokens.id_token).toBeDefined();

      // Validate ID token structure
      const idToken = tokens.id_token;
      const header = getJwtHeader(idToken);
      expect(header).toBeDefined();
      expect(header!.alg).toBe('RS256');
      expect(header!.kid).toBeDefined();

      // Decode and validate claims
      const payload = decodeJwt<IdTokenPayload>(idToken);
      expect(payload).toBeDefined();
      expect(payload!.iss).toBe('http://localhost:3000/test');
      expect(payload!.sub).toBe('test-user-001');
      expect(payload!.aud).toBe(confidentialClientId);
      expect(payload!.nonce).toBe(nonce);
      expect(payload!.exp).toBeDefined();
      expect(payload!.iat).toBeDefined();

      // Profile claims
      expect(payload!.name).toBe('Test User');

      // Email claims
      expect(payload!.email).toBe('test@example.com');
      expect(payload!.email_verified).toBe(true);
    });

    it('should verify ID token signature with JWKS', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      const tokens = await tokenRes.json();

      // Fetch JWKS
      const jwksRes = await app.request(`/${tenantSlug}/.well-known/jwks.json`);
      const jwks = await jwksRes.json();

      // Verify signature using JWKS
      const jwksSet = jose.createLocalJWKSet(jwks);
      const { payload } = await jose.jwtVerify(tokens.id_token, jwksSet, {
        issuer: 'http://localhost:3000/test',
        audience: confidentialClientId,
      });

      expect(payload.sub).toBe('test-user-001');
    });

    it('should not include ID token without openid scope', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'profile'); // No openid
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      const tokens = await tokenRes.json();
      expect(tokens.id_token).toBeUndefined();
    });
  });

  // ==========================================================================
  // Consent Flow
  // ==========================================================================
  describe('Consent Flow', () => {
    let consentClientId: string;
    let consentClientSecret: string;

    beforeAll(async () => {
      // Create a client that requires consent
      const { client, clientSecret } = await storage.clients.create({
        tenantId: tenantId,
        clientType: 'confidential',
        authMethod: 'client_secret_basic',
        name: 'Third Party App',
        redirectUris: ['http://localhost:3001/callback'],
        allowedGrants: ['authorization_code', 'refresh_token'],
        allowedScopes: ['openid', 'profile', 'email'],
        requireConsent: true,
        firstParty: false,
      });
      consentClientId = client.clientId;
      consentClientSecret = clientSecret!;
    });

    it('should return consent_required when user has not consented', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Clear any existing consent
      await userAuthenticator.revokeConsent(tenantId, 'test-user-001', consentClientId);

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', consentClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Should return JSON with consent_required
      expect(authRes.status).toBe(200);
      const body = await authRes.json();
      expect(body.consent_required).toBe(true);
      expect(body.client).toBeDefined();
      expect(body.client.name).toBe('Third Party App');
      expect(body.scopes).toBeDefined();
      expect(body.params).toBeDefined();
    });

    it('should complete flow when user grants consent via POST', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Clear any existing consent
      await userAuthenticator.revokeConsent(tenantId, 'test-user-001', consentClientId);

      // POST with consent=true
      const res = await app.request(`/${tenantSlug}/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          response_type: 'code',
          client_id: consentClientId,
          redirect_uri: 'http://localhost:3001/callback',
          scope: 'openid profile email',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          consent: 'true',
        }),
      });

      // Should redirect with code
      expect(res.status).toBe(302);
      const location = res.headers.get('Location');
      expect(location).toBeDefined();
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('code')).toBeDefined();
    });

    it('should redirect with error when user denies consent', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const state = 'test-state';

      // Clear consent
      await userAuthenticator.revokeConsent(tenantId, 'test-user-001', consentClientId);

      // POST with consent=false
      const res = await app.request(`/${tenantSlug}/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          response_type: 'code',
          client_id: consentClientId,
          redirect_uri: 'http://localhost:3001/callback',
          scope: 'openid profile email',
          state,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          consent: 'false',
        }),
      });

      // Should redirect with access_denied error
      expect(res.status).toBe(302);
      const location = res.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('access_denied');
      expect(redirectUrl.searchParams.get('state')).toBe(state);
    });

    it('should skip consent for requests with previously granted scopes', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Pre-save consent
      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        consentClientId,
        ['openid', 'profile', 'email']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', consentClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile'); // Subset of consented scopes
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Should redirect directly with code (no consent prompt)
      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      expect(new URL(location!).searchParams.get('code')).toBeDefined();
    });
  });

  // ==========================================================================
  // Bearer Token Middleware
  // ==========================================================================
  describe('Bearer Token Middleware', () => {
    let protectedApp: Hono<{ Variables: OAuthVariables }>;
    let validAccessToken: string;

    beforeAll(async () => {
      // Create a protected API app with error handler
      protectedApp = new Hono<{ Variables: OAuthVariables }>();

      // Add error handler to convert OAuthErrors to proper responses
      protectedApp.onError((err, c) => {
        if (err && typeof err === 'object' && 'statusCode' in err) {
          const oauthErr = err as { statusCode: number; code: string; description?: string };
          return c.json(
            { error: oauthErr.code, error_description: oauthErr.description },
            oauthErr.statusCode as 400 | 401 | 403
          );
        }
        return c.json({ error: 'server_error' }, 500);
      });

      // Add tenant resolution
      protectedApp.use(
        '/:tenant/*',
        tenantResolver({
          tenantStorage: storage.tenants,
          signingKeyStorage: storage.signingKeys,
        })
      );

      // Protected endpoint requiring api:read scope
      protectedApp.get(
        '/:tenant/api/data',
        bearerAuth({
          signingKeyStorage: storage.signingKeys,
          revokedTokenStorage: storage.revokedTokens,
          requiredScopes: ['api:read'],
        }),
        (c) => {
          const token = c.get('accessToken');
          return c.json({
            message: 'Protected data',
            client_id: token?.client_id,
            scope: token?.scope,
          });
        }
      );

      // Protected endpoint requiring api:write scope
      protectedApp.post(
        '/:tenant/api/data',
        bearerAuth({
          signingKeyStorage: storage.signingKeys,
          revokedTokenStorage: storage.revokedTokens,
          requiredScopes: ['api:write'],
        }),
        (c) => c.json({ message: 'Data written' })
      );

      // Get a valid access token
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read api:write',
        }),
      });
      const tokens = await tokenRes.json();
      validAccessToken = tokens.access_token;
    });

    it('should allow access with valid bearer token', async () => {
      const res = await protectedApp.request(`/${tenantSlug}/api/data`, {
        headers: {
          'Authorization': `Bearer ${validAccessToken}`,
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.message).toBe('Protected data');
      expect(body.client_id).toBe(confidentialClientId);
    });

    it('should reject request without authorization header', async () => {
      const res = await protectedApp.request(`/${tenantSlug}/api/data`);

      expect(res.status).toBe(401);
      expect(res.headers.get('WWW-Authenticate')).toContain('Bearer');
    });

    it('should reject invalid token format', async () => {
      const res = await protectedApp.request(`/${tenantSlug}/api/data`, {
        headers: {
          'Authorization': 'Bearer invalid-token-format',
        },
      });

      expect(res.status).toBe(401);
      expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token');
    });

    it('should reject revoked token', async () => {
      // Get a new token to revoke
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read',
        }),
      });
      const { access_token } = await tokenRes.json();

      // Revoke it
      await app.request(`/${tenantSlug}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: access_token,
          token_type_hint: 'access_token',
        }),
      });

      // Try to use revoked token
      const res = await protectedApp.request(`/${tenantSlug}/api/data`, {
        headers: {
          'Authorization': `Bearer ${access_token}`,
        },
      });

      expect(res.status).toBe(401);
    });

    it('should reject token with insufficient scope', async () => {
      // Get token with only api:read scope
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read', // Only read, not write
        }),
      });
      const { access_token } = await tokenRes.json();

      // Try to access endpoint requiring api:write
      const res = await protectedApp.request(`/${tenantSlug}/api/data`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${access_token}`,
        },
      });

      expect(res.status).toBe(403);
      expect(res.headers.get('WWW-Authenticate')).toContain('insufficient_scope');
    });
  });

  // ==========================================================================
  // PKCE Edge Cases
  // ==========================================================================
  describe('PKCE Edge Cases', () => {
    it('should reject unsupported code_challenge_method (plain)', async () => {
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', 'some-challenge');
      authUrl.searchParams.set('code_challenge_method', 'plain'); // Not allowed per RFC 9700

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toContain('S256');
    });

    it('should reject invalid code_challenge format (wrong length)', async () => {
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', 'too-short'); // Must be 43 chars for S256
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
    });

    it('should reject code_verifier that is too short', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      // Try with short verifier
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: 'short', // Must be 43-128 chars
        }),
      });

      expect(tokenRes.status).toBe(400);
    });
  });

  // ==========================================================================
  // Device Code Polling (slow_down)
  // ==========================================================================
  describe('Device Code Polling', () => {
    it('should return slow_down when polling too fast', async () => {
      // Get device code
      const deviceRes = await app.request(`/${tenantSlug}/device_authorization`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: confidentialClientId,
          scope: 'openid profile',
        }),
      });

      const { device_code, interval } = await deviceRes.json();
      expect(interval).toBeDefined();

      // First poll (should work)
      const poll1 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        }),
      });
      expect(poll1.status).toBe(400);
      const body1 = await poll1.json();
      expect(body1.error).toBe('authorization_pending');

      // Immediate second poll (should get slow_down)
      const poll2 = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        }),
      });
      expect(poll2.status).toBe(400);
      const body2 = await poll2.json();
      expect(body2.error).toBe('slow_down');
    });

    it('should return invalid_grant for unknown device code', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: 'non-existent-device-code',
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_grant');
    });
  });

  // ==========================================================================
  // Scope Validation Edge Cases
  // ==========================================================================
  describe('Scope Validation', () => {
    it('should reject scopes not allowed by client', async () => {
      // Create a client with limited scopes
      const { client: limitedClient, clientSecret: limitedSecret } = await storage.clients.create({
        tenantId: tenantId,
        clientType: 'confidential',
        authMethod: 'client_secret_basic',
        name: 'Limited Scope Client',
        redirectUris: ['http://localhost:3001/callback'],
        allowedGrants: ['client_credentials'],
        allowedScopes: ['api:read'], // Only api:read
      });

      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(limitedClient.clientId, limitedSecret!),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read api:write', // api:write not allowed
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe('invalid_scope');
    });

    it('should use default scopes when none requested', async () => {
      // The confidential client has default scopes of 'openid profile'
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      // No scope parameter - should use defaults
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      expect(authRes.status).toBe(302);

      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json();
      expect(tokens.scope).toContain('openid');
      expect(tokens.scope).toContain('profile');
    });

    it('should filter out user scopes for client_credentials grant', async () => {
      // Client credentials shouldn't get openid/profile/email scopes
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'openid profile email api:read', // openid/profile/email should be filtered
        }),
      });

      expect(res.status).toBe(200);
      const tokens = await res.json();
      // Should only have api:read, not user scopes
      expect(tokens.scope).toBe('api:read');
    });
  });

  // ==========================================================================
  // Access Token Validation
  // ==========================================================================
  describe('Access Token Validation', () => {
    it('should return valid JWT access token structure', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'api:read',
        }),
      });

      const tokens = await res.json();
      const accessToken = tokens.access_token;

      // Validate header
      const header = getJwtHeader(accessToken);
      expect(header).toBeDefined();
      expect(header!.alg).toBe('RS256');
      expect(header!.kid).toBeDefined();
      expect(header!.typ).toBe('at+jwt'); // RFC 9068

      // Validate payload
      const payload = decodeJwt<AccessTokenPayload>(accessToken);
      expect(payload).toBeDefined();
      expect(payload!.iss).toBe('http://localhost:3000/test');
      expect(payload!.sub).toBe(confidentialClientId); // Subject is client for client_credentials
      expect(payload!.aud).toBe(confidentialClientId);
      expect(payload!.client_id).toBe(confidentialClientId);
      expect(payload!.scope).toBe('api:read');
      expect(payload!.exp).toBeDefined();
      expect(payload!.iat).toBeDefined();
      expect(payload!.jti).toBeDefined();
      expect(payload!.token_type).toBe('access_token');
      expect(payload!.tenant_id).toBe(tenantId);
    });

    it('should verify access token signature with JWKS', async () => {
      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json();

      // Fetch JWKS
      const jwksRes = await app.request(`/${tenantSlug}/.well-known/jwks.json`);
      const jwks = await jwksRes.json();

      // Verify the JWKS structure is valid and we can verify the token
      expect(jwks.keys).toBeDefined();
      expect(jwks.keys.length).toBeGreaterThan(0);

      // Verify signature using jose
      const jwksSet = jose.createLocalJWKSet(jwks as jose.JSONWebKeySet);
      const { payload } = await jose.jwtVerify(tokens.access_token, jwksSet, {
        issuer: 'http://localhost:3000/test',
      });

      expect(payload.client_id).toBe(confidentialClientId);
    });
  });

  // ==========================================================================
  // Rate Limiting
  // ==========================================================================
  describe('Rate Limiting', () => {
    it('should include rate limit headers in responses', async () => {
      const res = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }),
      });

      expect(res.headers.get('X-RateLimit-Limit')).toBeDefined();
      expect(res.headers.get('X-RateLimit-Remaining')).toBeDefined();
      expect(res.headers.get('X-RateLimit-Reset')).toBeDefined();
    });
  });

  // ==========================================================================
  // Refresh Token Introspection
  // ==========================================================================
  describe('Refresh Token Introspection', () => {
    it('should introspect refresh token with token_type_hint', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Save consent before the authorization request
      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile', 'offline_access']
      );

      // Get refresh token via authorization code flow
      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile offline_access');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);

      // Verify we got a redirect (not a consent page)
      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      expect(location).toBeDefined();

      const redirectUrl = new URL(location!);
      const code = redirectUrl.searchParams.get('code');
      expect(code).toBeDefined();

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      expect(tokenRes.status).toBe(200);
      const tokens = await tokenRes.json() as any;
      const refresh_token = tokens.refresh_token;
      expect(refresh_token).toBeDefined();

      // Introspect refresh token
      const introspectRes = await app.request(`/${tenantSlug}/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          token: refresh_token,
          token_type_hint: 'refresh_token',
        }),
      });

      expect(introspectRes.status).toBe(200);
      const body = await introspectRes.json() as any;
      expect(body.active).toBe(true);
      expect(body.client_id).toBe(confidentialClientId);
      expect(body.sub).toBe('test-user-001');
      expect(body.scope).toContain('offline_access');
    });
  });

  // ==========================================================================
  // UserInfo Endpoint
  // ==========================================================================
  describe('UserInfo Endpoint', () => {
    async function getAccessToken(scopes: string[]): Promise<string> {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        scopes
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', scopes.join(' '));
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      const tokenRes = await app.request(`/${tenantSlug}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(confidentialClientId, confidentialClientSecret),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: codeVerifier,
        }),
      });

      const tokens = await tokenRes.json() as any;
      return tokens.access_token;
    }

    it('should return user info for valid access token', async () => {
      const accessToken = await getAccessToken(['openid', 'profile', 'email']);

      const res = await app.request(`/${tenantSlug}/userinfo`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      expect(res.status).toBe(200);
      const userInfo = await res.json() as any;
      expect(userInfo.sub).toBe('test-user-001');
    });

    it('should include profile claims when profile scope granted', async () => {
      const accessToken = await getAccessToken(['openid', 'profile']);

      const res = await app.request(`/${tenantSlug}/userinfo`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      expect(res.status).toBe(200);
      const userInfo = await res.json() as any;
      expect(userInfo.sub).toBe('test-user-001');
      expect(userInfo.name).toBe('Test User');
    });

    it('should include email claims when email scope granted', async () => {
      const accessToken = await getAccessToken(['openid', 'email']);

      const res = await app.request(`/${tenantSlug}/userinfo`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      expect(res.status).toBe(200);
      const userInfo = await res.json() as any;
      expect(userInfo.sub).toBe('test-user-001');
      expect(userInfo.email).toBe('test@example.com');
      expect(userInfo.email_verified).toBe(true);
    });

    it('should reject request without access token', async () => {
      const res = await app.request(`/${tenantSlug}/userinfo`);

      expect(res.status).toBe(400);
    });

    it('should reject request with invalid access token', async () => {
      const res = await app.request(`/${tenantSlug}/userinfo`, {
        headers: {
          'Authorization': 'Bearer invalid-token',
        },
      });

      expect(res.status).toBe(401);
    });

    it('should support POST method', async () => {
      const accessToken = await getAccessToken(['openid']);

      const res = await app.request(`/${tenantSlug}/userinfo`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          access_token: accessToken,
        }),
      });

      expect(res.status).toBe(200);
      const userInfo = await res.json() as any;
      expect(userInfo.sub).toBe('test-user-001');
    });
  });

  // ==========================================================================
  // End Session (Logout) Endpoint
  // ==========================================================================
  describe('End Session Endpoint', () => {
    it('should return logout confirmation page without parameters', async () => {
      const res = await app.request(`/${tenantSlug}/end_session`);

      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('Logged Out');
    });

    it('should accept POST method', async () => {
      const res = await app.request(`/${tenantSlug}/end_session`, {
        method: 'POST',
      });

      expect(res.status).toBe(200);
    });

    it('should reject invalid post_logout_redirect_uri', async () => {
      const res = await app.request(
        `/${tenantSlug}/end_session?post_logout_redirect_uri=http://evil.com&client_id=${confidentialClientId}`
      );

      expect(res.status).toBe(400);
    });
  });

  // ==========================================================================
  // Dynamic Client Registration
  // ==========================================================================
  describe('Dynamic Client Registration', () => {
    it('should register a new public client', async () => {
      const res = await app.request(`/${tenantSlug}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
          token_endpoint_auth_method: 'none',
          client_name: 'Test Dynamic Client',
          grant_types: ['authorization_code', 'refresh_token'],
        }),
      });

      // Should fail without initial access token when allowOpenRegistration is false
      expect(res.status).toBe(400);
    });
  });

  // ==========================================================================
  // Response Mode Support
  // ==========================================================================
  describe('Response Mode Support', () => {
    it('should support response_mode=form_post', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      authUrl.searchParams.set('response_mode', 'form_post');

      const res = await app.request(authUrl.pathname + authUrl.search);

      // response_mode=form_post returns HTML with auto-submit form
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('<form');
      expect(html).toContain('method="POST"');
      expect(html).toContain('action="http://localhost:3001/callback"');
      expect(html).toContain('name="code"');
    });

    it('should support response_mode=fragment', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      await userAuthenticator.saveConsent(
        tenantId,
        'test-user-001',
        confidentialClientId,
        ['openid', 'profile']
      );

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      authUrl.searchParams.set('response_mode', 'fragment');

      const res = await app.request(authUrl.pathname + authUrl.search);

      expect(res.status).toBe(302);
      const location = res.headers.get('Location')!;
      // Fragment mode puts params in hash
      expect(location).toContain('#code=');
    });

    it('should reject invalid response_mode', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      const authUrl = new URL(`http://localhost/${tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      authUrl.searchParams.set('response_mode', 'invalid');

      const res = await app.request(authUrl.pathname + authUrl.search);

      expect(res.status).toBe(400);
    });
  });

  // ==========================================================================
  // OpenID Configuration (Extended)
  // ==========================================================================
  describe('OpenID Configuration (Extended)', () => {
    it('should include new OIDC endpoints in discovery', async () => {
      const res = await app.request(`/${tenantSlug}/.well-known/openid-configuration`);
      expect(res.status).toBe(200);

      const config = await res.json() as any;

      // Check new endpoints
      expect(config.userinfo_endpoint).toBe('http://localhost:3000/test/userinfo');
      expect(config.end_session_endpoint).toBe('http://localhost:3000/test/end_session');
      expect(config.registration_endpoint).toBe('http://localhost:3000/test/register');

      // Check response modes
      expect(config.response_modes_supported).toContain('query');
      expect(config.response_modes_supported).toContain('fragment');
      expect(config.response_modes_supported).toContain('form_post');

      // Check logout support
      expect(config.backchannel_logout_supported).toBe(true);
      expect(config.backchannel_logout_session_supported).toBe(true);
      expect(config.frontchannel_logout_supported).toBe(true);
      expect(config.frontchannel_logout_session_supported).toBe(true);

      // Check claims parameter support
      expect(config.claims_parameter_supported).toBe(true);

      // Check extended claims
      expect(config.claims_supported).toContain('given_name');
      expect(config.claims_supported).toContain('family_name');
      expect(config.claims_supported).toContain('address');
      expect(config.claims_supported).toContain('phone_number');
      expect(config.claims_supported).toContain('acr');
      expect(config.claims_supported).toContain('amr');
    });
  });
});
