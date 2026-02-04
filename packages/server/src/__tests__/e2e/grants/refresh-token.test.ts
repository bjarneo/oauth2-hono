import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  setupTestContext,
  resetUser,
  basicAuth,
  generateCodeVerifier,
  generateCodeChallenge,
  type TestContext,
  type TokenResponse,
  type ErrorResponse,
} from '../test-setup.js';

describe('Refresh Token Grant', () => {
  let ctx: TestContext;
  let refreshToken: string;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(async () => {
    resetUser(ctx.userAuthenticator);

    // Get a refresh token via authorization code flow
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile', 'offline_access']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile offline_access');
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
    refreshToken = tokens.refresh_token!;
  });

  it('should issue new tokens with valid refresh token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    expect(res.status).toBe(200);

    const tokens = await res.json() as TokenResponse;
    expect(tokens.access_token).toBeDefined();
    expect(tokens.refresh_token).toBeDefined();
    expect(tokens.refresh_token).not.toBe(refreshToken); // Should be rotated
  });

  it('should allow scope downgrading', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: 'openid profile', // Subset of original scopes
      }),
    });

    expect(res.status).toBe(200);
    const tokens = await res.json() as TokenResponse;
    expect(tokens.scope).toBe('openid profile');
  });

  it('should reject scope upgrading', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: 'openid profile email api:read', // api:read wasn't in original
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_scope');
  });

  it('should reject reused refresh token (rotation detection)', async () => {
    // First refresh (should succeed and rotate)
    const res1 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });
    expect(res1.status).toBe(200);

    // Try to reuse original refresh token (should fail - already revoked)
    const res2 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    expect(res2.status).toBe(400);
    const body = await res2.json() as ErrorResponse;
    expect(body.error).toBe('invalid_grant');
  });

  it('should reject invalid refresh token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'invalid-refresh-token',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_grant');
  });
});

describe('Refresh Token Introspection', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should introspect refresh token with token_type_hint', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Save consent before the authorization request
    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile', 'offline_access']
    );

    // Get refresh token via authorization code flow
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile offline_access');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

    // Verify we got a redirect (not a consent page)
    expect(authRes.status).toBe(302);
    const location = authRes.headers.get('Location');
    expect(location).toBeDefined();

    const redirectUrl = new URL(location!);
    const code = redirectUrl.searchParams.get('code');
    expect(code).toBeDefined();

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
    const refresh_token = tokens.refresh_token;
    expect(refresh_token).toBeDefined();

    // Introspect refresh token
    const introspectRes = await ctx.app.request(`/${ctx.tenantSlug}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: refresh_token!,
        token_type_hint: 'refresh_token',
      }),
    });

    expect(introspectRes.status).toBe(200);
    const body = await introspectRes.json() as {
      active: boolean;
      client_id: string;
      sub: string;
      scope: string;
    };
    expect(body.active).toBe(true);
    expect(body.client_id).toBe(ctx.confidentialClientId);
    expect(body.sub).toBe('test-user-001');
    expect(body.scope).toContain('offline_access');
  });
});
