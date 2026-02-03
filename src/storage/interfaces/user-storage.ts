import type { Context } from 'hono';
import type { User, UserConsent } from '../../types/user.js';

/**
 * Authentication result from the user authenticator
 */
export type AuthenticationResult =
  | { authenticated: true; user: User }
  | { authenticated: false; redirectTo: string };

/**
 * Pluggable user authenticator interface
 *
 * Implementations of this interface handle:
 * - User authentication (login page, session validation, etc.)
 * - Consent management
 *
 * The OAuth server does NOT manage users or authentication - it delegates
 * to this interface. This allows integration with any user management system.
 *
 * Example implementation:
 *
 * ```typescript
 * class MyUserAuthenticator implements IUserAuthenticator {
 *   async authenticate(ctx: Context): Promise<AuthenticationResult> {
 *     const sessionId = getCookie(ctx, 'session_id');
 *     if (!sessionId) {
 *       // Redirect to login, saving the current URL for return
 *       const returnUrl = ctx.req.url;
 *       return { authenticated: false, redirectTo: `/login?return=${encodeURIComponent(returnUrl)}` };
 *     }
 *
 *     const user = await this.sessionStore.getUser(sessionId);
 *     if (!user) {
 *       return { authenticated: false, redirectTo: '/login' };
 *     }
 *
 *     return { authenticated: true, user };
 *   }
 *
 *   async getConsent(tenantId: string, userId: string, clientId: string): Promise<string[] | null> {
 *     return this.consentStore.get(tenantId, userId, clientId);
 *   }
 *
 *   async saveConsent(tenantId: string, userId: string, clientId: string, scopes: string[]): Promise<void> {
 *     await this.consentStore.save(tenantId, userId, clientId, scopes);
 *   }
 * }
 * ```
 */
export interface IUserAuthenticator {
  /**
   * Authenticate the current request
   *
   * This is called during the authorization flow to determine if the user
   * is logged in. Implementations should:
   *
   * 1. Check for existing session (cookie, token, etc.)
   * 2. If authenticated, return the user
   * 3. If not authenticated, return a redirect URL to your login page
   *
   * The login page should:
   * 1. Authenticate the user
   * 2. Create a session
   * 3. Redirect back to the original authorization URL
   *
   * @param ctx - Hono request context
   * @returns User if authenticated, or redirect URL if not
   */
  authenticate(ctx: Context): Promise<AuthenticationResult>;

  /**
   * Get previously granted consent for a user-client pair
   *
   * @param tenantId - Tenant identifier
   * @param userId - User identifier
   * @param clientId - OAuth client identifier
   * @returns Array of consented scopes, or null if no consent recorded
   */
  getConsent(tenantId: string, userId: string, clientId: string): Promise<string[] | null>;

  /**
   * Save user consent for a client
   *
   * @param tenantId - Tenant identifier
   * @param userId - User identifier
   * @param clientId - OAuth client identifier
   * @param scopes - Scopes the user consented to
   */
  saveConsent(tenantId: string, userId: string, clientId: string, scopes: string[]): Promise<void>;

  /**
   * Revoke user consent for a client
   *
   * @param tenantId - Tenant identifier
   * @param userId - User identifier
   * @param clientId - OAuth client identifier
   */
  revokeConsent(tenantId: string, userId: string, clientId: string): Promise<void>;

  /**
   * Optional: Get user by ID
   * Used for token introspection to get user details
   */
  getUserById?(tenantId: string, userId: string): Promise<User | null>;
}

/**
 * Simple in-memory consent storage for testing
 * Production implementations should use a database
 */
export interface IConsentStorage {
  /**
   * Get consent for a user-client pair
   */
  get(tenantId: string, userId: string, clientId: string): Promise<UserConsent | null>;

  /**
   * Save consent
   */
  save(consent: UserConsent): Promise<void>;

  /**
   * Revoke consent
   */
  revoke(tenantId: string, userId: string, clientId: string): Promise<void>;

  /**
   * List all consents for a user
   */
  listByUser(tenantId: string, userId: string): Promise<UserConsent[]>;
}
