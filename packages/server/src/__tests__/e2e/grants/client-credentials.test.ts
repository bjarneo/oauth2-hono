import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { setupTestContext, resetUser, basicAuth, type TestContext, type TokenResponse, type ErrorResponse } from '../test-setup.js';

describe('Client Credentials Grant', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should issue access token for valid credentials', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

    expect(res.status).toBe(200);

    const body = await res.json() as TokenResponse;
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBeDefined();
    expect(body.refresh_token).toBeUndefined(); // No refresh token for client credentials
  });

  it('should reject invalid client credentials', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, 'wrong-secret'),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('invalid_client');
  });

  it('should reject public clients', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: ctx.publicClientId,
      }),
    });

    expect(res.status).toBe(401);
  });

  it('should reject missing grant_type', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
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

  it('should reject unsupported grant type', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
      },
      body: new URLSearchParams({
        grant_type: 'password', // Not supported
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as ErrorResponse;
    expect(body.error).toBe('unsupported_grant_type');
  });
});
