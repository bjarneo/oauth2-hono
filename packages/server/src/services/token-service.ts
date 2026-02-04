import type { Tenant, SigningKey } from '../types/tenant.js';
import type { OAuthClient } from '../types/client.js';
import type { User } from '../types/user.js';
import type { TokenResponse, IdTokenPayload, AccessTokenPayload, ClaimsRequest } from '../types/index.js';
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
  sessionId?: string;
  claims?: ClaimsRequest;
  acr?: string;
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
      sessionId,
      claims,
      acr,
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
        sessionId,
      });

      response.refresh_token = refreshToken;
    }

    // Generate ID token if openid scope is present and user is provided
    if (scopeService.isOpenIdScope(scopes) && user) {
      const idTokenPayload = this.buildIdTokenPayload({
        tenant,
        client,
        user,
        scopes,
        nonce,
        now,
        accessTokenTtl,
        claims,
        acr,
        sessionId,
      });

      response.id_token = await signIdToken(idTokenPayload, signingKey);
    }

    return response;
  }

  /**
   * Build ID token payload with all applicable claims
   */
  private buildIdTokenPayload(options: {
    tenant: Tenant;
    client: OAuthClient;
    user: User;
    scopes: string[];
    nonce?: string;
    now: number;
    accessTokenTtl: number;
    claims?: ClaimsRequest;
    acr?: string;
    sessionId?: string;
  }): IdTokenPayload {
    const { tenant, client, user, scopes, nonce, now, accessTokenTtl, claims, acr, sessionId } = options;

    const idTokenPayload: IdTokenPayload = {
      iss: tenant.issuer,
      sub: user.id,
      aud: client.clientId,
      exp: now + accessTokenTtl, // ID token same lifetime as access token
      iat: now,
      auth_time: user.authTime ?? now,
      nonce,
    };

    // Add authentication context claims
    if (acr || user.acr) {
      idTokenPayload.acr = acr || user.acr;
    }

    if (user.amr && user.amr.length > 0) {
      idTokenPayload.amr = user.amr;
    }

    // Add authorized party if audience could have multiple values
    idTokenPayload.azp = client.clientId;

    // Add session ID for logout support
    if (sessionId) {
      idTokenPayload.sid = sessionId;
    }

    // Add profile claims if profile scope is present
    if (scopeService.hasScope(scopes, 'profile')) {
      if (user.name) idTokenPayload.name = user.name;
      if (user.givenName) idTokenPayload.given_name = user.givenName;
      if (user.familyName) idTokenPayload.family_name = user.familyName;
      if (user.middleName) idTokenPayload.middle_name = user.middleName;
      if (user.nickname) idTokenPayload.nickname = user.nickname;
      if (user.preferredUsername) idTokenPayload.preferred_username = user.preferredUsername;
      if (user.profile) idTokenPayload.profile = user.profile;
      if (user.picture) idTokenPayload.picture = user.picture;
      if (user.website) idTokenPayload.website = user.website;
      if (user.gender) idTokenPayload.gender = user.gender;
      if (user.birthdate) idTokenPayload.birthdate = user.birthdate;
      if (user.zoneinfo) idTokenPayload.zoneinfo = user.zoneinfo;
      if (user.locale) idTokenPayload.locale = user.locale;
      if (user.updatedAt) idTokenPayload.updated_at = user.updatedAt;
    }

    // Add email claims if email scope is present
    if (scopeService.hasScope(scopes, 'email')) {
      if (user.email) idTokenPayload.email = user.email;
      if (user.emailVerified !== undefined) {
        idTokenPayload.email_verified = user.emailVerified;
      }
    }

    // Add address claims if address scope is present
    if (scopeService.hasScope(scopes, 'address')) {
      if (user.address) idTokenPayload.address = user.address;
    }

    // Add phone claims if phone scope is present
    if (scopeService.hasScope(scopes, 'phone')) {
      if (user.phoneNumber) idTokenPayload.phone_number = user.phoneNumber;
      if (user.phoneNumberVerified !== undefined) {
        idTokenPayload.phone_number_verified = user.phoneNumberVerified;
      }
    }

    // Process claims parameter if provided
    if (claims?.id_token) {
      this.applyClaimsRequest(idTokenPayload, user, claims.id_token);
    }

    return idTokenPayload;
  }

  /**
   * Apply claims request to add specific requested claims
   */
  private applyClaimsRequest(
    payload: IdTokenPayload,
    user: User,
    requestedClaims: Record<string, any>
  ): void {
    for (const claimName of Object.keys(requestedClaims)) {
      // Skip if claim is already set
      if ((payload as any)[claimName] !== undefined) {
        continue;
      }

      // Map claim name to user property
      const userValue = this.getUserClaimValue(user, claimName);
      if (userValue !== undefined) {
        (payload as any)[claimName] = userValue;
      }
    }
  }

  /**
   * Get a claim value from the user object
   */
  private getUserClaimValue(user: User, claimName: string): any {
    const claimMap: Record<string, () => any> = {
      sub: () => user.id,
      name: () => user.name,
      given_name: () => user.givenName,
      family_name: () => user.familyName,
      middle_name: () => user.middleName,
      nickname: () => user.nickname,
      preferred_username: () => user.preferredUsername,
      profile: () => user.profile,
      picture: () => user.picture,
      website: () => user.website,
      gender: () => user.gender,
      birthdate: () => user.birthdate,
      zoneinfo: () => user.zoneinfo,
      locale: () => user.locale,
      updated_at: () => user.updatedAt,
      email: () => user.email,
      email_verified: () => user.emailVerified,
      address: () => user.address,
      phone_number: () => user.phoneNumber,
      phone_number_verified: () => user.phoneNumberVerified,
    };

    const getter = claimMap[claimName];
    return getter ? getter() : undefined;
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
