import type { AuthorizationCode, CreateAuthorizationCodeInput } from '../../types/token.js';
import type { IAuthorizationCodeStorage } from '../interfaces/authorization-code-storage.js';
import { generateId, generateAuthorizationCode, hashToken } from '../../crypto/index.js';

/**
 * In-memory authorization code storage implementation
 */
export class MemoryAuthorizationCodeStorage implements IAuthorizationCodeStorage {
  private codes = new Map<string, AuthorizationCode>();
  private hashIndex = new Map<string, string>(); // `${tenantId}:${hash}` -> id

  async create(input: CreateAuthorizationCodeInput): Promise<{ code: AuthorizationCode; value: string }> {
    const id = generateId();
    const codeValue = generateAuthorizationCode();
    const codeHash = hashToken(codeValue);
    const now = new Date();

    const code: AuthorizationCode = {
      id,
      tenantId: input.tenantId,
      clientId: input.clientId,
      userId: input.userId,
      codeHash,
      redirectUri: input.redirectUri,
      scope: input.scope,
      codeChallenge: input.codeChallenge,
      codeChallengeMethod: input.codeChallengeMethod,
      nonce: input.nonce,
      state: input.state,
      expiresAt: input.expiresAt,
      issuedAt: now,
    };

    this.codes.set(id, code);
    this.hashIndex.set(`${input.tenantId}:${codeHash}`, id);

    return { code, value: codeValue };
  }

  async findByHash(tenantId: string, codeHash: string): Promise<AuthorizationCode | null> {
    const id = this.hashIndex.get(`${tenantId}:${codeHash}`);
    if (!id) return null;
    return this.codes.get(id) ?? null;
  }

  async findByValue(tenantId: string, codeValue: string): Promise<AuthorizationCode | null> {
    const codeHash = hashToken(codeValue);
    return this.findByHash(tenantId, codeHash);
  }

  async consume(tenantId: string, codeValue: string): Promise<AuthorizationCode | null> {
    const codeHash = hashToken(codeValue);
    const id = this.hashIndex.get(`${tenantId}:${codeHash}`);
    if (!id) return null;

    const code = this.codes.get(id);
    if (!code) return null;

    // Check if already used
    if (code.usedAt) {
      return null;
    }

    // Check if expired
    if (code.expiresAt < new Date()) {
      return null;
    }

    // Mark as used (atomic in single-threaded JS)
    const usedCode: AuthorizationCode = {
      ...code,
      usedAt: new Date(),
    };
    this.codes.set(id, usedCode);

    return usedCode;
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const now = new Date();
    let deleted = 0;

    for (const [id, code] of this.codes) {
      if (code.tenantId === tenantId && code.expiresAt < now) {
        this.hashIndex.delete(`${code.tenantId}:${code.codeHash}`);
        this.codes.delete(id);
        deleted++;
      }
    }

    return deleted;
  }
}
