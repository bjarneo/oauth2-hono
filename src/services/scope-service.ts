import type { Tenant } from '../types/tenant.js';
import type { OAuthClient } from '../types/client.js';
import { OAuthError } from '../errors/oauth-error.js';

/**
 * Service for OAuth scope validation and manipulation
 */
export class ScopeService {
  /**
   * Parse a space-delimited scope string into an array
   */
  parseScopes(scopeString: string | undefined): string[] {
    if (!scopeString) {
      return [];
    }
    return scopeString
      .split(' ')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  /**
   * Convert scope array to space-delimited string
   */
  formatScopes(scopes: string[]): string {
    return scopes.join(' ');
  }

  /**
   * Validate requested scopes against tenant and client configuration
   *
   * @returns The validated scopes (may be reduced from requested)
   */
  validateScopes(
    requestedScopes: string[],
    tenant: Tenant,
    client: OAuthClient
  ): string[] {
    // If no scopes requested, use client defaults
    if (requestedScopes.length === 0) {
      return client.defaultScopes ?? [];
    }

    const validScopes: string[] = [];
    const invalidScopes: string[] = [];

    for (const scope of requestedScopes) {
      // Check if scope is allowed by tenant
      if (!tenant.allowedScopes.includes(scope)) {
        invalidScopes.push(scope);
        continue;
      }

      // Check if scope is allowed by client
      if (!client.allowedScopes.includes(scope)) {
        invalidScopes.push(scope);
        continue;
      }

      validScopes.push(scope);
    }

    // If any invalid scopes, throw error
    if (invalidScopes.length > 0) {
      throw OAuthError.invalidScope(
        `Invalid or unauthorized scopes: ${invalidScopes.join(', ')}`
      );
    }

    return validScopes;
  }

  /**
   * Check if a scope set includes a specific scope
   */
  hasScope(scopes: string[], scope: string): boolean {
    return scopes.includes(scope);
  }

  /**
   * Check if a scope set includes all required scopes
   */
  hasAllScopes(scopes: string[], requiredScopes: string[]): boolean {
    return requiredScopes.every((scope) => scopes.includes(scope));
  }

  /**
   * Check if a scope set includes any of the specified scopes
   */
  hasAnyScope(scopes: string[], anyScopes: string[]): boolean {
    return anyScopes.some((scope) => scopes.includes(scope));
  }

  /**
   * Filter scopes to only include those from a subset
   * Used when downgrading scopes during refresh token rotation
   */
  filterScopes(scopes: string[], allowedScopes: string[]): string[] {
    return scopes.filter((scope) => allowedScopes.includes(scope));
  }

  /**
   * Check if the scopes include 'offline_access' (needed for refresh tokens)
   */
  hasOfflineAccess(scopes: string[]): boolean {
    return this.hasScope(scopes, 'offline_access');
  }

  /**
   * Check if the scopes include 'openid' (OIDC flow)
   */
  isOpenIdScope(scopes: string[]): boolean {
    return this.hasScope(scopes, 'openid');
  }

  /**
   * Get profile-related scopes
   */
  getProfileScopes(scopes: string[]): string[] {
    const profileScopes = ['profile', 'email', 'address', 'phone'];
    return scopes.filter((scope) => profileScopes.includes(scope));
  }
}

// Singleton instance
export const scopeService = new ScopeService();
