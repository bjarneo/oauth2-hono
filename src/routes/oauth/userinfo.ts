import { Hono } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';
import type { UserInfoResponse } from '../../types/token.js';
import type { User } from '../../types/user.js';
import type { IUserAuthenticator } from '../../storage/interfaces/user-storage.js';
import type { ISigningKeyStorage } from '../../storage/interfaces/tenant-storage.js';
import { verifyAccessToken } from '../../crypto/jwt.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { scopeService } from '../../services/scope-service.js';

export interface UserInfoRoutesOptions {
  signingKeyStorage: ISigningKeyStorage;
  userAuthenticator?: IUserAuthenticator;
}

/**
 * Build UserInfo response based on granted scopes
 */
function buildUserInfoResponse(user: User, scopes: string[]): UserInfoResponse {
  const response: UserInfoResponse = {
    sub: user.id,
  };

  // Profile scope claims
  if (scopeService.hasScope(scopes, 'profile')) {
    if (user.name) response.name = user.name;
    if (user.givenName) response.given_name = user.givenName;
    if (user.familyName) response.family_name = user.familyName;
    if (user.middleName) response.middle_name = user.middleName;
    if (user.nickname) response.nickname = user.nickname;
    if (user.preferredUsername) response.preferred_username = user.preferredUsername;
    if (user.profile) response.profile = user.profile;
    if (user.picture) response.picture = user.picture;
    if (user.website) response.website = user.website;
    if (user.gender) response.gender = user.gender;
    if (user.birthdate) response.birthdate = user.birthdate;
    if (user.zoneinfo) response.zoneinfo = user.zoneinfo;
    if (user.locale) response.locale = user.locale;
    if (user.updatedAt) response.updated_at = user.updatedAt;
  }

  // Email scope claims
  if (scopeService.hasScope(scopes, 'email')) {
    if (user.email) response.email = user.email;
    if (user.emailVerified !== undefined) response.email_verified = user.emailVerified;
  }

  // Address scope claims
  if (scopeService.hasScope(scopes, 'address')) {
    if (user.address) response.address = user.address;
  }

  // Phone scope claims
  if (scopeService.hasScope(scopes, 'phone')) {
    if (user.phoneNumber) response.phone_number = user.phoneNumber;
    if (user.phoneNumberVerified !== undefined) {
      response.phone_number_verified = user.phoneNumberVerified;
    }
  }

  return response;
}

/**
 * Create UserInfo endpoint
 *
 * GET/POST /:tenant/userinfo
 *
 * Returns claims about the authenticated user based on the access token
 * and granted scopes.
 *
 * OpenID Connect Core 1.0 Section 5.3
 */
export function createUserInfoRoutes(options: UserInfoRoutesOptions) {
  const { signingKeyStorage, userAuthenticator } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  const handleUserInfo = async (c: any) => {
    const tenant = c.get('tenant');

    // Extract bearer token from Authorization header or POST body
    let accessToken: string | undefined;

    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      accessToken = authHeader.slice(7);
    } else if (c.req.method === 'POST') {
      const body = await c.req.parseBody();
      accessToken = body['access_token'] as string | undefined;
    }

    if (!accessToken) {
      c.header('WWW-Authenticate', 'Bearer');
      throw OAuthError.invalidRequest('Missing access token');
    }

    // Get signing keys for token verification
    const signingKeys = await signingKeyStorage.listByTenant(tenant.id);
    if (signingKeys.length === 0) {
      throw OAuthError.serverError('No signing keys configured');
    }

    // Verify the access token
    let payload: any;
    let verified = false;

    for (const key of signingKeys) {
      try {
        payload = await verifyAccessToken(accessToken, key, {
          issuer: tenant.issuer,
        });
        verified = true;
        break;
      } catch {
        // Try next key
      }
    }

    if (!verified || !payload) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      throw OAuthError.invalidToken('Access token is invalid or expired');
    }

    // Check that the token has openid scope
    const scopes = scopeService.parseScopes(payload.scope);
    if (!scopeService.isOpenIdScope(scopes)) {
      c.header('WWW-Authenticate', 'Bearer error="insufficient_scope"');
      throw OAuthError.insufficientScope('Token does not have openid scope');
    }

    // Get user information
    const userId = payload.sub;

    // Try to get user from authenticator
    let user: User | null = null;

    if (userAuthenticator?.getUserById) {
      user = await userAuthenticator.getUserById(tenant.id, userId);
    }

    // If no user found, return minimal response with just sub
    if (!user) {
      return c.json({ sub: userId });
    }

    // Build response based on scopes
    const response = buildUserInfoResponse(user, scopes);

    // Set appropriate headers
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');

    return c.json(response);
  };

  // Both GET and POST are supported per OIDC spec
  router.get('/', handleUserInfo);
  router.post('/', handleUserInfo);

  return router;
}
