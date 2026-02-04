/**
 * OIDC Address Claim structure
 */
export interface AddressClaim {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

/**
 * User representation for OAuth flows
 */
export interface User {
  id: string;
  username?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  nickname?: string;
  preferredUsername?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  updatedAt?: number;
  email?: string;
  emailVerified?: boolean;
  address?: AddressClaim;
  phoneNumber?: string;
  phoneNumberVerified?: boolean;
  authTime?: number;
  acr?: string;
  amr?: string[];
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

/**
 * Session information for logout
 */
export interface UserSession {
  sessionId: string;
  userId: string;
  tenantId: string;
  clientIds: string[];
  createdAt: Date;
  lastActivityAt: Date;
}
