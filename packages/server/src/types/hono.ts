import type { Context } from 'hono';
import type { Tenant, SigningKey } from './tenant.js';
import type { AuthenticatedClient } from './client.js';
import type { User } from './user.js';
import type { AccessTokenPayload } from './token.js';

/**
 * Extended Hono context variables for OAuth
 */
export interface OAuthVariables {
  tenant: Tenant;
  signingKey: SigningKey;
  client?: AuthenticatedClient;
  user?: User;
  accessToken?: AccessTokenPayload;
}

/**
 * OAuth-aware Hono context
 */
export type OAuthContext = Context<{ Variables: OAuthVariables }>;

/**
 * Context with authenticated client
 */
export interface AuthenticatedClientContext extends OAuthContext {
  get(key: 'client'): AuthenticatedClient;
}

/**
 * Context with authenticated user (from bearer token)
 */
export interface AuthenticatedUserContext extends OAuthContext {
  get(key: 'accessToken'): AccessTokenPayload;
}

/**
 * Rate limit info
 */
export interface RateLimitInfo {
  remaining: number;
  reset: number;
  total: number;
}
