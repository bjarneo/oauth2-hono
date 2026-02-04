import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
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
  type JWKSResponse,
} from './test-setup.js';
import { decodeJwt, getJwtHeader } from '../../crypto/jwt.js';
import type { AccessTokenPayload, IdTokenPayload } from '../../types/token.js';

interface IntrospectionResponse {
  active: boolean;
  client_id?: string;
  token_type?: string;
  exp?: number;
}

describe('Token Introspection', () => {
  let ctx: TestContext;
  let accessToken: string;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(async () => {
    resetUser(ctx.userAuthenticator);

    // Get an access token
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

    const tokens = await res.json() as TokenResponse;
    accessToken = tokens.access_token;
  });

  it('should return active=true for valid token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: accessToken,
      }),
    });

    expect(res.status).toBe(200);

    const body = await res.json() as IntrospectionResponse;
    expect(body.active).toBe(true);
    expect(body.client_id).toBe(ctx.confidentialClientId);
    expect(body.token_type).toBe('Bearer');
    expect(body.exp).toBeDefined();
  });

  it('should return active=false for invalid token', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: 'invalid-token',
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as IntrospectionResponse;
    expect(body.active).toBe(false);
  });

  it('should require client authentication', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/introspect`, {
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
    await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: accessToken,
        token_type_hint: 'access_token',
      }),
    });

    // Introspect revoked token
    const res = await ctx.app.request(`/${ctx.tenantSlug}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: accessToken,
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as IntrospectionResponse;
    expect(body.active).toBe(false);
  });
});

describe('Token Revocation', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should revoke access token', async () => {
    // Get token
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    const { access_token } = await tokenRes.json() as TokenResponse;

    // Revoke token
    const revokeRes = await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
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

    // RFC 7009: Always returns 200 OK
    expect(revokeRes.status).toBe(200);
  });

  it('should revoke refresh token', async () => {
    // Get refresh token via auth code flow
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

    const { refresh_token } = await tokenRes.json() as TokenResponse;

    // Revoke refresh token
    const revokeRes = await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
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

    expect(revokeRes.status).toBe(200);

    // Try to use revoked refresh token
    const refreshRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refresh_token!,
      }),
    });

    expect(refreshRes.status).toBe(400);
    const body = await refreshRes.json() as ErrorResponse;
    expect(body.error).toBe('invalid_grant');
  });

  it('should return 200 even for invalid token (RFC 7009)', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        token: 'completely-invalid-token',
      }),
    });

    // RFC 7009 requires always returning 200 to prevent token fishing
    expect(res.status).toBe(200);
  });

  it('should require token parameter', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_request');
  });
});

describe('ID Token Validation', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return valid ID token with openid scope', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const nonce = generateRandomBase64Url(16);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['openid', 'profile', 'email']
    );

    // Authorization request with nonce
    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('nonce', nonce);

    const authRes = await ctx.app.request(authUrl.pathname + authUrl.search);
    const code = new URL(authRes.headers.get('Location')!).searchParams.get('code');

    // Token exchange
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
    expect(tokens.id_token).toBeDefined();

    // Validate ID token structure
    const idToken = tokens.id_token!;
    const header = getJwtHeader(idToken);
    expect(header).toBeDefined();
    expect(header!.alg).toBe('RS256');
    expect(header!.kid).toBeDefined();

    // Decode and validate claims
    const payload = decodeJwt(idToken) as IdTokenPayload | null;
    expect(payload).toBeDefined();
    expect(payload!.iss).toBe('http://localhost:3000/test');
    expect(payload!.sub).toBe('test-user-001');
    expect(payload!.aud).toBe(ctx.confidentialClientId);
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

    // Fetch JWKS
    const jwksRes = await ctx.app.request(`/${ctx.tenantSlug}/.well-known/jwks.json`);
    const jwks = await jwksRes.json() as jose.JSONWebKeySet;

    // Verify signature using JWKS
    const jwksSet = jose.createLocalJWKSet(jwks);
    const { payload } = await jose.jwtVerify(tokens.id_token!, jwksSet, {
      issuer: 'http://localhost:3000/test',
      audience: ctx.confidentialClientId,
    });

    expect(payload.sub).toBe('test-user-001');
  });

  it('should not include ID token without openid scope', async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    await ctx.userAuthenticator.saveConsent(
      ctx.tenantId,
      'test-user-001',
      ctx.confidentialClientId,
      ['profile']
    );

    const authUrl = new URL(`http://localhost/${ctx.tenantSlug}/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', ctx.confidentialClientId);
    authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
    authUrl.searchParams.set('scope', 'profile'); // No openid
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
    expect(tokens.id_token).toBeUndefined();
  });
});

describe('Access Token Validation', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return valid JWT access token structure', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

    const tokens = await res.json() as TokenResponse;
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
    expect(payload!.sub).toBe(ctx.confidentialClientId); // Subject is client for client_credentials
    expect(payload!.aud).toBe(ctx.confidentialClientId);
    expect(payload!.client_id).toBe(ctx.confidentialClientId);
    expect(payload!.scope).toBe('api:read');
    expect(payload!.exp).toBeDefined();
    expect(payload!.iat).toBeDefined();
    expect(payload!.jti).toBeDefined();
    expect(payload!.token_type).toBe('access_token');
    expect(payload!.tenant_id).toBe(ctx.tenantId);
  });

  it('should verify access token signature with JWKS', async () => {
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json() as TokenResponse;

    // Fetch JWKS
    const jwksRes = await ctx.app.request(`/${ctx.tenantSlug}/.well-known/jwks.json`);
    const jwks = await jwksRes.json() as JWKSResponse;

    // Verify the JWKS structure is valid and we can verify the token
    expect(jwks.keys).toBeDefined();
    expect(jwks.keys.length).toBeGreaterThan(0);

    // Verify signature using jose
    const jwksSet = jose.createLocalJWKSet(jwks as jose.JSONWebKeySet);
    const { payload } = await jose.jwtVerify(tokens.access_token, jwksSet, {
      issuer: 'http://localhost:3000/test',
    });

    expect(payload.client_id).toBe(ctx.confidentialClientId);
  });
});
