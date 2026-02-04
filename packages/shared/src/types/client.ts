import type { GrantType } from './oauth.js';

/**
 * OAuth 2.0 Client Types
 */
export type ClientType = 'confidential' | 'public';

/**
 * Client Authentication Methods
 */
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt'
  | 'none';

/**
 * JSON Web Key Set
 */
export interface JsonWebKeySet {
  keys: JsonWebKey[];
}

export interface JsonWebKey {
  kty: string;
  use?: string;
  key_ops?: string[];
  alg?: string;
  kid?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

/**
 * OAuth 2.0 Client
 */
export interface OAuthClient {
  id: string;
  tenantId: string;
  clientId: string;
  clientSecretHash?: string;
  clientType: ClientType;
  authMethod: ClientAuthMethod;
  name: string;
  description?: string;
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  redirectUris: string[];
  allowedGrants: GrantType[];
  allowedScopes: string[];
  defaultScopes?: string[];
  jwksUri?: string;
  jwks?: JsonWebKeySet;
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  requireConsent?: boolean;
  firstParty?: boolean;
  postLogoutRedirectUris?: string[];
  backchannelLogoutUri?: string;
  backchannelLogoutSessionRequired?: boolean;
  frontchannelLogoutUri?: string;
  frontchannelLogoutSessionRequired?: boolean;
  registrationAccessToken?: string;
  registrationClientUri?: string;
  contacts?: string[];
  softwareId?: string;
  softwareVersion?: string;
  softwareStatement?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Client creation input
 */
export interface CreateClientInput {
  tenantId: string;
  clientType: ClientType;
  authMethod: ClientAuthMethod;
  name: string;
  description?: string;
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  redirectUris: string[];
  allowedGrants: GrantType[];
  allowedScopes: string[];
  defaultScopes?: string[];
  jwksUri?: string;
  jwks?: JsonWebKeySet;
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  requireConsent?: boolean;
  firstParty?: boolean;
  postLogoutRedirectUris?: string[];
  backchannelLogoutUri?: string;
  backchannelLogoutSessionRequired?: boolean;
  frontchannelLogoutUri?: string;
  frontchannelLogoutSessionRequired?: boolean;
  contacts?: string[];
  softwareId?: string;
  softwareVersion?: string;
  softwareStatement?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Client update input
 */
export interface UpdateClientInput {
  name?: string;
  description?: string;
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  redirectUris?: string[];
  allowedGrants?: GrantType[];
  allowedScopes?: string[];
  defaultScopes?: string[];
  jwksUri?: string;
  jwks?: JsonWebKeySet;
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  requireConsent?: boolean;
  firstParty?: boolean;
  postLogoutRedirectUris?: string[];
  backchannelLogoutUri?: string;
  backchannelLogoutSessionRequired?: boolean;
  frontchannelLogoutUri?: string;
  frontchannelLogoutSessionRequired?: boolean;
  contacts?: string[];
  softwareId?: string;
  softwareVersion?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Authenticated client context
 */
export interface AuthenticatedClient {
  client: OAuthClient;
  authMethod: ClientAuthMethod;
}
