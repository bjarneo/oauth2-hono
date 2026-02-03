import type { GrantType } from './oauth.js';

/**
 * OAuth 2.0 Client Types
 * RFC 6749 Section 2.1
 */
export type ClientType = 'confidential' | 'public';

/**
 * Client Authentication Methods
 * RFC 6749 Section 2.3, OpenID Connect Core Section 9
 */
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt'
  | 'none';

/**
 * OAuth 2.0 Client
 */
export interface OAuthClient {
  id: string;
  tenantId: string;
  clientId: string; // Public identifier
  clientSecretHash?: string; // Hashed secret (null for public clients)
  clientType: ClientType;
  authMethod: ClientAuthMethod;
  name: string;
  description?: string;
  redirectUris: string[]; // Registered redirect URIs (exact match required)
  allowedGrants: GrantType[];
  allowedScopes: string[];
  defaultScopes?: string[];
  jwksUri?: string; // For private_key_jwt authentication
  jwks?: JsonWebKeySet; // Inline JWKS for private_key_jwt
  accessTokenTtl?: number; // Override tenant default
  refreshTokenTtl?: number; // Override tenant default
  requireConsent?: boolean; // Whether to prompt user for consent
  firstParty?: boolean; // Skip consent for first-party apps
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

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
 * Client creation input
 */
export interface CreateClientInput {
  tenantId: string;
  clientType: ClientType;
  authMethod: ClientAuthMethod;
  name: string;
  description?: string;
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
  metadata?: Record<string, unknown>;
}

/**
 * Client update input
 */
export interface UpdateClientInput {
  name?: string;
  description?: string;
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
  metadata?: Record<string, unknown>;
}

/**
 * Authenticated client context
 */
export interface AuthenticatedClient {
  client: OAuthClient;
  authMethod: ClientAuthMethod;
}
