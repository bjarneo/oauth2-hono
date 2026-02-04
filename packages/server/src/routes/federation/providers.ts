import type { IdentityProviderTemplate } from '../../storage/interfaces/identity-provider-storage.js';

/**
 * Pre-configured provider endpoints and settings
 */
export interface ProviderConfig {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  issuer?: string;
  defaultScopes: string[];
  supportsOidc: boolean;
}

/**
 * Provider templates with pre-configured endpoints
 */
export const providerTemplates: Record<IdentityProviderTemplate, ProviderConfig> = {
  google: {
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    issuer: 'https://accounts.google.com',
    defaultScopes: ['openid', 'profile', 'email'],
    supportsOidc: true,
  },
  github: {
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userinfoEndpoint: 'https://api.github.com/user',
    defaultScopes: ['read:user', 'user:email'],
    supportsOidc: false,
  },
  microsoft: {
    authorizationEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
    jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
    issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
    defaultScopes: ['openid', 'profile', 'email'],
    supportsOidc: true,
  },
  apple: {
    authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
    tokenEndpoint: 'https://appleid.apple.com/auth/token',
    jwksUri: 'https://appleid.apple.com/auth/keys',
    issuer: 'https://appleid.apple.com',
    defaultScopes: ['openid', 'name', 'email'],
    supportsOidc: true,
  },
  facebook: {
    authorizationEndpoint: 'https://www.facebook.com/v18.0/dialog/oauth',
    tokenEndpoint: 'https://graph.facebook.com/v18.0/oauth/access_token',
    userinfoEndpoint: 'https://graph.facebook.com/me?fields=id,name,email,picture',
    defaultScopes: ['email', 'public_profile'],
    supportsOidc: false,
  },
  twitter: {
    authorizationEndpoint: 'https://twitter.com/i/oauth2/authorize',
    tokenEndpoint: 'https://api.twitter.com/2/oauth2/token',
    userinfoEndpoint: 'https://api.twitter.com/2/users/me',
    defaultScopes: ['tweet.read', 'users.read'],
    supportsOidc: false,
  },
  linkedin: {
    authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
    tokenEndpoint: 'https://www.linkedin.com/oauth/v2/accessToken',
    userinfoEndpoint: 'https://api.linkedin.com/v2/userinfo',
    defaultScopes: ['openid', 'profile', 'email'],
    supportsOidc: true,
  },
  generic_oidc: {
    authorizationEndpoint: '',
    tokenEndpoint: '',
    defaultScopes: ['openid', 'profile', 'email'],
    supportsOidc: true,
  },
  generic_oauth2: {
    authorizationEndpoint: '',
    tokenEndpoint: '',
    defaultScopes: [],
    supportsOidc: false,
  },
};

/**
 * Get provider configuration, merging template with custom settings
 */
export function getProviderConfig(
  template: IdentityProviderTemplate | undefined,
  customEndpoints: {
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    userinfoEndpoint?: string;
    jwksUri?: string;
    issuer?: string;
  }
): ProviderConfig {
  const base = template ? providerTemplates[template] : providerTemplates.generic_oauth2;

  return {
    authorizationEndpoint: customEndpoints.authorizationEndpoint || base.authorizationEndpoint,
    tokenEndpoint: customEndpoints.tokenEndpoint || base.tokenEndpoint,
    userinfoEndpoint: customEndpoints.userinfoEndpoint || base.userinfoEndpoint,
    jwksUri: customEndpoints.jwksUri || base.jwksUri,
    issuer: customEndpoints.issuer || base.issuer,
    defaultScopes: base.defaultScopes,
    supportsOidc: base.supportsOidc,
  };
}

/**
 * Default attribute mapping for different providers
 */
export const defaultAttributeMappings: Partial<Record<IdentityProviderTemplate, Record<string, string>>> = {
  google: {
    id: 'sub',
    email: 'email',
    name: 'name',
    givenName: 'given_name',
    familyName: 'family_name',
    picture: 'picture',
    emailVerified: 'email_verified',
  },
  github: {
    id: 'id',
    email: 'email',
    name: 'name',
    picture: 'avatar_url',
  },
  microsoft: {
    id: 'sub',
    email: 'email',
    name: 'name',
    givenName: 'given_name',
    familyName: 'family_name',
    picture: 'picture',
  },
  facebook: {
    id: 'id',
    email: 'email',
    name: 'name',
    picture: 'picture.data.url',
  },
  linkedin: {
    id: 'sub',
    email: 'email',
    name: 'name',
    givenName: 'given_name',
    familyName: 'family_name',
    picture: 'picture',
  },
};
