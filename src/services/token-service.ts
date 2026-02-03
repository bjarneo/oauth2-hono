import type { Tenant, SigningKey } from '../types/tenant.js';
import type { OAuthClient } from '../types/client.js';
import type { User } from '../types/user.js';
import type { TokenResponse, IdTokenPayload, AccessTokenPayload } from '../types/index.js';
import type { IRefreshTokenStorage } from '../storage/interfaces/token-storage.js';
import { signAccessToken, signIdToken } from '../crypto/jwt.js';
import { scopeService } from './scope-service.js';
import { TOKEN_TYPE_BEARER } from '../config/constants.js';

export interface TokenGenerationOptions {
  tenant: Tenant;
  signingKey: SigningKey;
  client: OAuthClient;
  user?: User;
  scopes: string[];
  nonce?: string;
  refreshTokenStorage?: IRefreshTokenStorage;
  parentRefreshTokenId?: string;
  familyId?: string;
}

/**
 * Service for token generation
 */
export class TokenService {
  /**
   * Generate a complete token response
   */
  async generateTokenResponse(options: TokenGenerationOptions): Promise<TokenResponse> {
    const {
      tenant,
      signingKey,
      client,
      user,
      scopes,
      nonce,
      refreshTokenStorage,
      parentRefreshTokenId,
      familyId,
    } = options;

    const now = Math.floor(Date.now() / 1000);
    const accessTokenTtl = client.accessTokenTtl ?? tenant.accessTokenTtl;
    const refreshTokenTtl = client.refreshTokenTtl ?? tenant.refreshTokenTtl;

    // Build access token payload
    const accessTokenPayload: Omit<AccessTokenPayload, 'jti'> = {
      iss: tenant.issuer,
      sub: user?.id ?? client.clientId, // Subject is user ID or client ID for client_credentials
      aud: client.clientId,
      exp: now + accessTokenTtl,
      iat: now,
      client_id: client.clientId,
      scope: scopeService.formatScopes(scopes),
      token_type: 'access_token',
      tenant_id: tenant.id,
    };

    // Sign access token
    const accessToken = await signAccessToken(accessTokenPayload, signingKey);

    // Build response
    const response: TokenResponse = {
      access_token: accessToken,
      token_type: TOKEN_TYPE_BEARER,
      expires_in: accessTokenTtl,
    };

    // Add scope if it differs from requested
    if (scopes.length > 0) {
      response.scope = scopeService.formatScopes(scopes);
    }

    // Generate refresh token if offline_access scope is present and storage is provided
    if (scopeService.hasOfflineAccess(scopes) && refreshTokenStorage) {
      const expiresAt = new Date(Date.now() + refreshTokenTtl * 1000);

      const { value: refreshToken } = await refreshTokenStorage.create({
        tenantId: tenant.id,
        clientId: client.clientId,
        userId: user?.id,
        scope: scopeService.formatScopes(scopes),
        expiresAt,
        parentTokenId: parentRefreshTokenId,
        familyId,
      });

      response.refresh_token = refreshToken;
    }

    // Generate ID token if openid scope is present and user is provided
    if (scopeService.isOpenIdScope(scopes) && user) {
      const idTokenPayload: IdTokenPayload = {
        iss: tenant.issuer,
        sub: user.id,
        aud: client.clientId,
        exp: now + accessTokenTtl, // ID token same lifetime as access token
        iat: now,
        auth_time: now,
        nonce,
      };

      // Add profile claims if profile scope is present
      if (scopeService.hasScope(scopes, 'profile')) {
        if (user.name) idTokenPayload.name = user.name;
        if (user.picture) idTokenPayload.picture = user.picture;
      }

      // Add email claims if email scope is present
      if (scopeService.hasScope(scopes, 'email')) {
        if (user.email) idTokenPayload.email = user.email;
        if (user.emailVerified !== undefined) {
          idTokenPayload.email_verified = user.emailVerified;
        }
      }

      response.id_token = await signIdToken(idTokenPayload, signingKey);
    }

    return response;
  }

  /**
   * Generate tokens for client credentials grant
   */
  async generateClientCredentialsTokens(
    tenant: Tenant,
    signingKey: SigningKey,
    client: OAuthClient,
    scopes: string[]
  ): Promise<TokenResponse> {
    // Client credentials don't get refresh tokens or ID tokens
    const now = Math.floor(Date.now() / 1000);
    const accessTokenTtl = client.accessTokenTtl ?? tenant.accessTokenTtl;

    const accessTokenPayload: Omit<AccessTokenPayload, 'jti'> = {
      iss: tenant.issuer,
      sub: client.clientId,
      aud: client.clientId,
      exp: now + accessTokenTtl,
      iat: now,
      client_id: client.clientId,
      scope: scopeService.formatScopes(scopes),
      token_type: 'access_token',
      tenant_id: tenant.id,
    };

    const accessToken = await signAccessToken(accessTokenPayload, signingKey);

    const response: TokenResponse = {
      access_token: accessToken,
      token_type: TOKEN_TYPE_BEARER,
      expires_in: accessTokenTtl,
    };

    if (scopes.length > 0) {
      response.scope = scopeService.formatScopes(scopes);
    }

    return response;
  }
}

// Singleton instance
export const tokenService = new TokenService();
