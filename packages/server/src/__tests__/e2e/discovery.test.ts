import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { setupTestContext, resetUser, type TestContext, type OpenIDConfiguration, type JWKSResponse, type ErrorResponse } from './test-setup.js';

describe('Discovery & Health', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTestContext();
  });

  beforeEach(() => {
    resetUser(ctx.userAuthenticator);
  });

  // ==========================================================================
  // Health Check
  // ==========================================================================
  describe('Health Check', () => {
    it('should return OK status', async () => {
      const res = await ctx.app.request('/health');
      expect(res.status).toBe(200);
      const body = await res.json() as { status: string };
      expect(body).toEqual({ status: 'ok' });
    });
  });

  // ==========================================================================
  // Discovery Endpoints
  // ==========================================================================
  describe('Discovery Endpoints', () => {
    describe('OpenID Configuration', () => {
      it('should return valid OpenID configuration', async () => {
        const res = await ctx.app.request(`/${ctx.tenantSlug}/.well-known/openid-configuration`);
        expect(res.status).toBe(200);

        const config = await res.json() as OpenIDConfiguration;
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
        const res = await ctx.app.request('/unknown-tenant/.well-known/openid-configuration');
        expect(res.status).toBe(400);
        const body = await res.json() as ErrorResponse;
        expect(body.error).toBe('invalid_request');
      });
    });

    describe('JWKS', () => {
      it('should return valid JWKS', async () => {
        const res = await ctx.app.request(`/${ctx.tenantSlug}/.well-known/jwks.json`);
        expect(res.status).toBe(200);

        const jwks = await res.json() as JWKSResponse;
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
  // OpenID Configuration (Extended)
  // ==========================================================================
  describe('OpenID Configuration (Extended)', () => {
    it('should include new OIDC endpoints in discovery', async () => {
      const res = await ctx.app.request(`/${ctx.tenantSlug}/.well-known/openid-configuration`);
      expect(res.status).toBe(200);

      const config = await res.json() as OpenIDConfiguration;

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
