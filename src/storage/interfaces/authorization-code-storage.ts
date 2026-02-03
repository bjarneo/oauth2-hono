import type { AuthorizationCode, CreateAuthorizationCodeInput } from '../../types/token.js';

/**
 * Storage interface for authorization code management
 */
export interface IAuthorizationCodeStorage {
  /**
   * Create a new authorization code
   * Returns the code record and the plaintext code value
   */
  create(input: CreateAuthorizationCodeInput): Promise<{ code: AuthorizationCode; value: string }>;

  /**
   * Find an authorization code by its hash
   */
  findByHash(tenantId: string, codeHash: string): Promise<AuthorizationCode | null>;

  /**
   * Find an authorization code by plaintext value
   */
  findByValue(tenantId: string, codeValue: string): Promise<AuthorizationCode | null>;

  /**
   * Consume (mark as used) an authorization code atomically
   * Returns the code if successful, null if already used or not found
   * This MUST be atomic to prevent code reuse attacks
   */
  consume(tenantId: string, codeValue: string): Promise<AuthorizationCode | null>;

  /**
   * Delete expired authorization codes (cleanup)
   */
  deleteExpired(tenantId: string): Promise<number>;
}
