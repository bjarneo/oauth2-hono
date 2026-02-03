/**
 * OIDC Address Claim structure
 * OpenID Connect Core 1.0 Section 5.1.1
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
 * This is what the pluggable user authenticator returns
 *
 * Claims are organized by OIDC scope:
 * - openid: sub (id)
 * - profile: name, family_name, given_name, middle_name, nickname,
 *            preferred_username, profile, picture, website, gender,
 *            birthdate, zoneinfo, locale, updated_at
 * - email: email, email_verified
 * - address: address
 * - phone: phone_number, phone_number_verified
 */
export interface User {
  // Required: Subject identifier (unique user ID)
  id: string;

  // Profile scope claims
  username?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  nickname?: string;
  preferredUsername?: string;
  profile?: string; // URL of profile page
  picture?: string; // URL of profile picture
  website?: string;
  gender?: string;
  birthdate?: string; // ISO 8601 date (YYYY-MM-DD)
  zoneinfo?: string; // Time zone (e.g., "America/Los_Angeles")
  locale?: string; // Locale (e.g., "en-US")
  updatedAt?: number; // Unix timestamp of last profile update

  // Email scope claims
  email?: string;
  emailVerified?: boolean;

  // Address scope claims
  address?: AddressClaim;

  // Phone scope claims
  phoneNumber?: string;
  phoneNumberVerified?: boolean;

  // Authentication context
  authTime?: number; // Unix timestamp of authentication
  acr?: string; // Authentication Context Class Reference
  amr?: string[]; // Authentication Methods References

  // Custom claims
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
  clientIds: string[]; // Clients the user has authenticated with
  createdAt: Date;
  lastActivityAt: Date;
}
