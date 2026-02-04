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
  | 'client_secret_jwt'
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
  logoUri?: string;
  clientUri?: string; // Home page URL
  policyUri?: string; // Privacy policy URL
  tosUri?: string; // Terms of service URL
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

  // Logout configuration
  postLogoutRedirectUris?: string[]; // Allowed URIs for post-logout redirect
  backchannelLogoutUri?: string; // Back-channel logout endpoint
  backchannelLogoutSessionRequired?: boolean; // Require sid in logout token
  frontchannelLogoutUri?: string; // Front-channel logout endpoint
  frontchannelLogoutSessionRequired?: boolean; // Require sid in logout

  // Dynamic registration
  registrationAccessToken?: string; // Token for managing registration
  registrationClientUri?: string; // URI for managing registration

  // Additional metadata
  contacts?: string[]; // Contact emails
  softwareId?: string; // Software identifier
  softwareVersion?: string; // Software version
  softwareStatement?: string; // Signed JWT with client metadata

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

/**
 * Dynamic Client Registration Request
 * RFC 7591
 */
export interface ClientRegistrationRequest {
  redirect_uris: string[];
  token_endpoint_auth_method?: ClientAuthMethod;
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  jwks?: JsonWebKeySet;
  software_id?: string;
  software_version?: string;
  software_statement?: string;
  post_logout_redirect_uris?: string[];
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  frontchannel_logout_uri?: string;
  frontchannel_logout_session_required?: boolean;
}

/**
 * Dynamic Client Registration Response
 * RFC 7591
 */
export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
  registration_access_token?: string;
  registration_client_uri?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: ClientAuthMethod;
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  jwks?: JsonWebKeySet;
  software_id?: string;
  software_version?: string;
  post_logout_redirect_uris?: string[];
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;
  frontchannel_logout_uri?: string;
  frontchannel_logout_session_required?: boolean;
}
