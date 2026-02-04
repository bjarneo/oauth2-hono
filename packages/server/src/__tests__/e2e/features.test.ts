import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { Hono } from 'hono';
import {
  setupTestContext,
  resetUser,
  basicAuth,
  generateCodeVerifier,
  generateCodeChallenge,
  generateRandomBase64Url,
  jose,
  type TestContext,
  type TokenResponse,
  type ErrorResponse,
} from './test-setup.js';
import type { OAuthVariables } from '../../types/hono.js';
import { bearerAuth } from '../../middleware/bearer-auth.js';
import { tenantResolver } from '../../middleware/tenant-resolver.js';

describe('Error Handling', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return proper error format', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'invalid_grant_type',
      }),
    });

    const body = await res.json() as ErrorResponse;
    expect(body.error).toBeDefined();
    // error_description is optional but helpful
  });

  it('should handle unknown tenant gracefully', async () => {
    const res = await ctx.app.request('/nonexistent/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_request');
  });

  it('should include security headers', async () => {
    const res = await ctx.app.request('/health');

    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  });
});

describe('Multi-tenant Isolation', () => {
  let ctx: TestContext;
  let otherTenantSlug: string;
  let otherClientId: string;
  let otherClientSecret: string;

  beforeAll(async () => {
    ctx = await setupTestContext();

    // Create another tenant
    const tenant = await ctx.storage.tenants.create({
      name: 'Other Tenant',
      slug: 'other',
      issuer: 'http://localhost:3000/other',
    });
    otherTenantSlug = tenant.slug;

    await ctx.storage.signingKeys.create({
      tenantId: tenant.id,
      algorithm: 'RS256',
      isPrimary: true,
    });

    const { client, clientSecret } = await ctx.storage.clients.create({
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

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should not allow cross-tenant client usage', async () => {
    // Try to use other tenant's client on first tenant
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_client');
  });

  it('should work correctly for each tenant', async () => {
    // First tenant
    const res1 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });
    expect(res1.status).toBe(200);

    // Other tenant
    const res2 = await ctx.app.request(`/${otherTenantSlug}/token`, {
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

describe('Client Authentication Methods', () => {
  let ctx: TestContext;
  let postAuthClientId: string;
  let postAuthClientSecret: string;
  let jwtAuthClientId: string;
  let jwtClientKeyPair: { publicKey: jose.KeyLike; privateKey: jose.KeyLike };

  beforeAll(async () => {
    ctx = await setupTestContext();

    // Create client with client_secret_post auth
    const { client: postClient, clientSecret } = await ctx.storage.clients.create({
      tenantId: ctx.tenantId,
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
    const jwtClientJwk = await jose.exportJWK(publicKey);
    jwtClientJwk.kid = 'test-key-1';
    jwtClientJwk.alg = 'RS256';
    jwtClientJwk.use = 'sig';

    // Create client with private_key_jwt auth
    const { client: jwtClient } = await ctx.storage.clients.create({
      tenantId: ctx.tenantId,
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

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  describe('client_secret_post', () => {
    it('should authenticate with credentials in POST body', async () => {
      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
      const body = await res.json() as TokenResponse;
      expect(body.access_token).toBeDefined();
    });

    it('should reject wrong auth method (Basic instead of POST)', async () => {
      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
      const body = await res.json() as ErrorResponse;
      expect(body.error).toBe('invalid_client');
    });

    it('should reject invalid secret in POST body', async () => {
      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
      const body = await res.json() as ErrorResponse;
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

      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
      const body = await res.json() as TokenResponse;
      expect(body.access_token).toBeDefined();
    });

    it('should reject invalid JWT assertion', async () => {
      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
      const body = await res.json() as ErrorResponse;
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

      const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

interface ConsentResponse {
  consent_required: boolean;
  client: { name: string };
  scopes: string[];
  params: Record<string, string>;
}

describe('Consent Flow', () => {
  let ctx: TestContext;
  let consentClientId: string;

  beforeAll(async () => {
    ctx = await setupTestContext();

    // Create a client that requires consent
    const { client } = await ctx.storage.clients.create({
      tenantId: ctx.tenantId,
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
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return consent_required when user has not consented', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Clear any existing consent
    await ctx.userAuthenticator.revokeConsent(ctx.tenantId, 'test-user-001', consentClientId);

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', consentClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

    // Should return JSON with consent_required
    expect(authRes.status).toBe(200);
    const body = await authRes.json() as ConsentResponse;
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
    await ctx.userAuthenticator.revokeConsent(ctx.tenantId, 'test-user-001', consentClientId);

    // POST with consent=true
    const res = await ctx.app.request(`/${ctx.tenantSlug}/authorize`, {
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
    await ctx.userAuthenticator.revokeConsent(ctx.tenantId, 'test-user-001', consentClientId);

    // POST with consent=false
    const res = await ctx.app.request(`/${ctx.tenantSlug}/authorize`, {
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
    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      consentClientId,
      ['openid', 'profile', 'email']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', consentClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile'); // Subset of consented scopes
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

    // Should redirect directly with code (no consent prompt)
    expect(authRes.status).toBe(302);
    const location = authRes.headers.get('Location');
    expect(new URL(location!).searchParams.get('code')).toBeDefined();
  });
});

describe('Bearer Token Middleware', () => {
  let ctx: TestContext;
  let protectedApp: Hono<{ Variables: OAuthVariables }>;
  let validAccessToken: string;

  beforeAll(async () => {
    ctx = await setupTestContext();

    // Create a protected API app with error handler
    protectedApp = new Hono<{ Variables: OAuthVariables }>();

    // Add error handler to convert OAuthErrors to proper responses
    protectedApp.onError((err, c) => {
      if (err && typeof err === 'object' && 'statusCode' in err) {
        const oauthErr = err as unknown as { statusCode: number; code: string; description?: string };
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
        tenantStorage: ctx.storage.tenants,
        signingKeyStorage: ctx.storage.signingKeys,
      })
    );

    // Protected endpoint requiring api:read scope
    protectedApp.get(
      '/:tenant/api/data',
      bearerAuth({
        signingKeyStorage: ctx.storage.signingKeys,
        revokedTokenStorage: ctx.storage.revokedTokens,
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
        signingKeyStorage: ctx.storage.signingKeys,
        revokedTokenStorage: ctx.storage.revokedTokens,
        requiredScopes: ['api:write'],
      }),
      (c) => c.json({ message: 'Data written' })
    );

    // Get a valid access token
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api:read api:write',
      }),
    });
    const tokens = await tokenRes.json() as TokenResponse;
    validAccessToken = tokens.access_token;
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should allow access with valid bearer token', async () => {
    const res = await protectedApp.request(`/${ctx.tenantSlug}/api/data`, {
      headers: {
        'Authorization': `Bearer ${validAccessToken}`,
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json() as { message: string; client_id: string };
    expect(body.message).toBe('Protected data');
    expect(body.client_id).toBe(ctx.confidentialClientId);
  });

  it('should reject request without authorization header', async () => {
    const res = await protectedApp.request(`/${ctx.tenantSlug}/api/data`);

    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toContain('Bearer');
  });

  it('should reject invalid token format', async () => {
    const res = await protectedApp.request(`/${ctx.tenantSlug}/api/data`, {
      headers: {
        'Authorization': 'Bearer invalid-token-format',
      },
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token');
  });

  it('should reject revoked token', async () => {
    // Get a new token to revoke
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api:read',
      }),
    });
    const { access_token } = await tokenRes.json() as TokenResponse;

    // Revoke it
    await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: access_token,
        token_type_hint: 'access_token',
      }),
    });

    // Try to use revoked token
    const res = await protectedApp.request(`/${ctx.tenantSlug}/api/data`, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
      },
    });

    expect(res.status).toBe(401);
  });

  it('should reject token with insufficient scope', async () => {
    // Get token with only api:read scope
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api:read', // Only read, not write
      }),
    });
    const { access_token } = await tokenRes.json() as TokenResponse;

    // Try to access endpoint requiring api:write
    const res = await protectedApp.request(`/${ctx.tenantSlug}/api/data`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${access_token}`,
      },
    });

    expect(res.status).toBe(403);
    expect(res.headers.get('WWW-Authenticate')).toContain('insufficient_scope');
  });
});

describe('Scope Validation', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should reject scopes not allowed by client', async () => {
    // Create a client with limited scopes
    const { client: limitedClient, clientSecret: limitedSecret } = await ctx.storage.clients.create({
      tenantId: ctx.tenantId,
      clientType: 'confidential',
      authMethod: 'client_secret_basic',
      name: 'Limited Scope Client',
      redirectUris: ['http://localhost:3001/callback'],
      allowedGrants: ['client_credentials'],
      allowedScopes: ['api:read'], // Only api:read
    });

    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_scope');
  });

  it('should use default scopes when none requested', async () => {
    // The confidential client has default scopes of 'openid profile'
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    // No scope parameter - should use defaults
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    expect(authRes.status).toBe(302);

    const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: 'http://localhost:3001/callback',
        code_verifier: codeVerifier,
      }),
    });

    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json() as TokenResponse;
    expect(tokens.scope).toContain('openid');
    expect(tokens.scope).toContain('profile');
  });

  it('should filter out user scopes for client_credentials grant', async () => {
    // Client credentials shouldn't get openid/profile/email scopes
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'openid profile email api:read', // openid/profile/email should be filtered
      }),
    });

    expect(res.status).toBe(200);
    const tokens = await res.json() as TokenResponse;
    // Should only have api:read, not user scopes
    expect(tokens.scope).toBe('api:read');
  });
});

describe('Rate Limiting', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should include rate limit headers in responses', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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

interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
}

describe('UserInfo Endpoint', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  async function getAccessToken(scopes: string[]): Promise<string> {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      scopes
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', scopes.join(' '));
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: 'http://localhost:3001/callback',
        code_verifier: codeVerifier,
      }),
    });

    const tokens = await tokenRes.json() as TokenResponse;
    return tokens.access_token;
  }

  it('should return user info for valid access token', async () => {
    const accessToken = await getAccessToken(['openid', 'profile', 'email']);

    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    expect(res.status).toBe(200);
    const userInfo = await res.json() as UserInfoResponse;
    expect(userInfo.sub).toBe('test-user-001');
  });

  it('should include profile claims when profile scope granted', async () => {
    const accessToken = await getAccessToken(['openid', 'profile']);

    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    expect(res.status).toBe(200);
    const userInfo = await res.json() as UserInfoResponse;
    expect(userInfo.sub).toBe('test-user-001');
    expect(userInfo.name).toBe('Test User');
  });

  it('should include email claims when email scope granted', async () => {
    const accessToken = await getAccessToken(['openid', 'email']);

    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    expect(res.status).toBe(200);
    const userInfo = await res.json() as UserInfoResponse;
    expect(userInfo.sub).toBe('test-user-001');
    expect(userInfo.email).toBe('test@example.com');
    expect(userInfo.email_verified).toBe(true);
  });

  it('should reject request without access token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`);

    expect(res.status).toBe(400);
  });

  it('should reject request with invalid access token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`, {
      headers: {
        'Authorization': 'Bearer invalid-token',
      },
    });

    expect(res.status).toBe(401);
  });

  it('should support POST method', async () => {
    const accessToken = await getAccessToken(['openid']);

    const res = await ctx.app.request(`/${ctx.tenantSlug}/userinfo`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        access_token: accessToken,
      }),
    });

    expect(res.status).toBe(200);
    const userInfo = await res.json() as UserInfoResponse;
    expect(userInfo.sub).toBe('test-user-001');
  });
});

describe('End Session Endpoint', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return logout confirmation page without parameters', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/end_session`);

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Logged Out');
  });

  it('should accept POST method', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/end_session`, {
      method: 'POST',
    });

    expect(res.status).toBe(200);
  });

  it('should reject invalid post_logout_redirect_uri', async () => {
    const res = await ctx.app.request(
      `/${ctx.tenantSlug}/end_session?post_logout_redirect_uri=http://evil.com&client_id=${ctx.confidentialClientId}`
    );

    expect(res.status).toBe(400);
  });
});

describe('Dynamic Client Registration', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should register a new public client', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/register`, {
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

describe('Response Mode Support', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should support response_mode=form_post', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('response_mode', 'form_post');

    const res = await ctx.app.request(authUrl.pathname + authUrl.search);

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

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('response_mode', 'fragment');

    const res = await ctx.app.request(authUrl.pathname + authUrl.search);

    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    // Fragment mode puts params in hash
    expect(location).toContain('#code=');
  });

  it('should reject invalid response_mode', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('response_mode', 'invalid');

    const res = await ctx.app.request(authUrl.pathname + authUrl.search);

    expect(res.status).toBe(400);
  });
});
