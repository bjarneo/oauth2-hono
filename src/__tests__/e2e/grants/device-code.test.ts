import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { setupTestContext, resetUser, basicAuth, type TestContext } from '../test-setup.js';

describe('Device Code Grant', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should issue device code', async () => {
    const res = await ctx.app.request(`/${ctx.tenantSlug}/device_authorization`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: ctx.confidentialClientId,
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
    const deviceRes = await ctx.app.request(`/${ctx.tenantSlug}/device_authorization`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: ctx.confidentialClientId,
        scope: 'openid profile',
      }),
    });

    const { device_code } = await deviceRes.json();

    // Poll for token (should be pending)
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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
    const deviceRes = await ctx.app.request(`/${ctx.tenantSlug}/device_authorization`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: ctx.confidentialClientId,
        scope: 'openid profile',
      }),
    });

    const { device_code } = await deviceRes.json();

    // Simulate user authorization (directly in storage)
    // In real scenario, user would visit verification_uri
    const deviceCodeRecord = await ctx.storage.deviceCodes.findByValue(ctx.tenantId, device_code);
    if (deviceCodeRecord) {
      await ctx.storage.deviceCodes.authorize(deviceCodeRecord.id, 'test-user-001');
    }

    // Poll for token (should succeed now)
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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
    const deviceRes = await ctx.app.request(`/${ctx.tenantSlug}/device_authorization`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: ctx.confidentialClientId,
        scope: 'openid profile',
      }),
    });

    const { device_code } = await deviceRes.json();

    // Simulate user denial
    const deviceCodeRecord = await ctx.storage.deviceCodes.findByValue(ctx.tenantId, device_code);
    if (deviceCodeRecord) {
      await ctx.storage.deviceCodes.deny(deviceCodeRecord.id);
    }

    // Poll for token (should fail)
    const tokenRes = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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

describe('Device Code Polling', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  it('should return slow_down when polling too fast', async () => {
    // Get device code
    const deviceRes = await ctx.app.request(`/${ctx.tenantSlug}/device_authorization`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: ctx.confidentialClientId,
        scope: 'openid profile',
      }),
    });

    const { device_code, interval } = await deviceRes.json();
    expect(interval).toBeDefined();

    // First poll (should work)
    const poll1 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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
    const poll2 = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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
    const res = await ctx.app.request(`/${ctx.tenantSlug}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(ctx.confidentialClientId, ctx.confidentialClientSecret),
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
