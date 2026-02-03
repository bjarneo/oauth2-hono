import type { MiddlewareHandler } from 'hono';
import type { OAuthVariables } from '../types/hono.js';
import type { AccessTokenPayload } from '../types/token.js';
import type { IRevokedTokenStorage } from '../storage/interfaces/index.js';
import { OAuthError } from '../errors/oauth-error.js';
import { verifyJwt, getJwtHeader } from '../crypto/jwt.js';
import type { ISigningKeyStorage } from '../storage/interfaces/tenant-storage.js';
import { HEADER_AUTHORIZATION, HEADER_WWW_AUTHENTICATE } from '../config/constants.js';

export interface BearerAuthOptions {
  signingKeyStorage: ISigningKeyStorage;
  revokedTokenStorage: IRevokedTokenStorage;
  requiredScopes?: string[];
}

/**
 * Extract bearer token from Authorization header
 */
function extractBearerToken(authHeader: string): string | null {
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * Middleware to validate bearer tokens (JWT access tokens)
 *
 * Sets `accessToken` in context variables on success
 */
export function bearerAuth(options: BearerAuthOptions): MiddlewareHandler<{
  Variables: OAuthVariables;
}> {
  const { signingKeyStorage, revokedTokenStorage, requiredScopes } = options;

  return async (c, next) => {
    const tenant = c.get('tenant');
    if (!tenant) {
      throw OAuthError.serverError('Tenant not resolved');
    }

    const authHeader = c.req.header(HEADER_AUTHORIZATION);

    if (!authHeader) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}"`);
      throw OAuthError.invalidToken('Missing authorization header');
    }

    const token = extractBearerToken(authHeader);

    if (!token) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_request"`);
      throw OAuthError.invalidToken('Invalid authorization header format');
    }

    // Get the JWT header to find the key ID
    const header = getJwtHeader(token);
    if (!header || !header.kid) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_token"`);
      throw OAuthError.invalidToken('Invalid token format');
    }

    // Find the signing key
    const signingKey = await signingKeyStorage.findByKid(tenant.id, header.kid);
    if (!signingKey) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_token"`);
      throw OAuthError.invalidToken('Unknown signing key');
    }

    // Verify the token
    let payload: AccessTokenPayload;
    try {
      payload = await verifyJwt<AccessTokenPayload>(
        token,
        signingKey.publicKey,
        signingKey.algorithm,
        {
          issuer: tenant.issuer,
        }
      );
    } catch (error) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_token"`);
      throw OAuthError.invalidToken('Token verification failed');
    }

    // Check if token is revoked
    if (payload.jti) {
      const isRevoked = await revokedTokenStorage.isRevoked(tenant.id, payload.jti);
      if (isRevoked) {
        c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_token"`);
        throw OAuthError.invalidToken('Token has been revoked');
      }
    }

    // Check tenant matches
    if (payload.tenant_id !== tenant.id) {
      c.header(HEADER_WWW_AUTHENTICATE, `Bearer realm="${tenant.slug}", error="invalid_token"`);
      throw OAuthError.invalidToken('Token not valid for this tenant');
    }

    // Check required scopes
    if (requiredScopes && requiredScopes.length > 0) {
      const tokenScopes = payload.scope?.split(' ') ?? [];
      const hasAllScopes = requiredScopes.every((scope) => tokenScopes.includes(scope));

      if (!hasAllScopes) {
        c.header(
          HEADER_WWW_AUTHENTICATE,
          `Bearer realm="${tenant.slug}", error="insufficient_scope", scope="${requiredScopes.join(' ')}"`
        );
        throw OAuthError.insufficientScope(
          `Required scopes: ${requiredScopes.join(' ')}`
        );
      }
    }

    // Set the validated token payload in context
    c.set('accessToken', payload);

    await next();
  };
}

/**
 * Create bearer auth middleware with specific required scopes
 */
export function requireScopes(
  options: Omit<BearerAuthOptions, 'requiredScopes'>,
  scopes: string[]
): MiddlewareHandler<{ Variables: OAuthVariables }> {
  return bearerAuth({ ...options, requiredScopes: scopes });
}
