import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  setupTestContext,
  resetUser,
  basicAuth,
  generateCodeVerifier,
  generateCodeChallenge,
  type TestContext,
} from '../test-setup.js';

describe('Authorization Code Grant', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should complete full authorization code flow with PKCE', async () => {
    // Step 1: Generate PKCE values
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = 'random-state-value';

    // Pre-save consent for the user to skip consent screen (include offline_access for refresh token)
    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile', 'email', 'offline_access']
    );

    // Step 2: Authorization request (include offline_access to get refresh token)
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile email offline_access');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

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
    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.publicClientId,
      ['openid', 'profile']
    );

    // Authorization request
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.publicClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    expect(authRes.status).toBe(302);

    const location = authRes.headers.get('Location');
    const redirectUrl = new URL(location!);
    const code = redirectUrl.searchParams.get('code');

    // Token exchange without client secret (public client)
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: ctx.publicClientId,
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
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    // Missing code_challenge

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

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
    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile']
    );

    // Get authorization code
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    const location = authRes.headers.get('Location');
    const code = new URL(location!).searchParams.get('code');

    // Try to exchange with wrong verifier
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
        code_verifier: 'wrong-verifier-that-does-not-match-the-challenge',
      }),
    });

    expect(tokenRes.status).toBe(400);
    const body = await tokenRes.json();
    expect(body.error).toBe('invalid_grant');
  });

  it('should reject invalid redirect_uri', async () => {
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://malicious.com/callback');
    authUrl.searchParams.set('code_challenge', 'abc123');
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

    // Should return error directly (not redirect)
    expect(authRes.status).toBe(400);
    const body = await authRes.json();
    expect(body.error).toBe('invalid_request');
  });

  it('should reject reused authorization code', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile']
    );

    // Get authorization code
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    const location = authRes.headers.get('Location');
    const code = new URL(location!).searchParams.get('code');

    // First token exchange (should succeed)
    const tokenRes1 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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
    expect(tokenRes1.status).toBe(200);

    // Second token exchange (should fail - code already used)
    const tokenRes2 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

    expect(tokenRes2.status).toBe(400);
    const body = await tokenRes2.json();
    expect(body.error).toBe('invalid_grant');
  });

  // ==========================================================================
  // PKCE Edge Cases
  // ==========================================================================
  describe('PKCE Edge Cases', () => {
    it('should reject unsupported code_challenge_method (plain)', async () => {
      const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', ctx.confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', 'some-challenge');
      authUrl.searchParams.set('code_challenge_method', 'plain'); // Not allowed per RFC 9700

      const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
      expect(redirectUrl.searchParams.get('error_description')).toContain('S256');
    });

    it('should reject invalid code_challenge format (wrong length)', async () => {
      const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', ctx.confidentialClientId);
      authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
      authUrl.searchParams.set('scope', 'openid profile');
      authUrl.searchParams.set('code_challenge', 'too-short'); // Must be 43 chars for S256
      authUrl.searchParams.set('code_challenge_method', 'S256');

      const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get('Location');
      const redirectUrl = new URL(location!);
      expect(redirectUrl.searchParams.get('error')).toBe('invalid_request');
    });

    it('should reject code_verifier that is too short', async () => {
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

      const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
      const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

      // Try with short verifier
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
          code_verifier: 'short', // Must be 43-128 chars
        }),
      });

      expect(tokenRes.status).toBe(400);
    });
  });
});
