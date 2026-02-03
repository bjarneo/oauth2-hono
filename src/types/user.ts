/**
 * User representation for OAuth flows
 * This is what the pluggable user authenticator returns
 */
export interface User {
  id: string;
  username?: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  picture?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User consent record
 */
export interface UserConsent {
  userId: string;
  clientId: string;
  tenantId: string;
  scopes: string[];
  grantedAt: Date;
  expiresAt?: Date;
}
