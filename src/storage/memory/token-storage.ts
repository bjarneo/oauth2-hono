import type { RefreshToken, CreateRefreshTokenInput, RevokedToken } from '../../types/token.js';
import type { IRefreshTokenStorage, IRevokedTokenStorage } from '../interfaces/token-storage.js';
import { generateId, generateRefreshToken, generateFamilyId, hashToken } from '../../crypto/index.js';

/**
 * In-memory refresh token storage implementation
 */
export class MemoryRefreshTokenStorage implements IRefreshTokenStorage {
  private tokens = new Map<string, RefreshToken>();
  private hashIndex = new Map<string, string>(); // `${tenantId}:${hash}` -> id
  private familyIndex = new Map<string, Set<string>>(); // `${tenantId}:${familyId}` -> Set<id>
  private userClientIndex = new Map<string, Set<string>>(); // `${tenantId}:${userId}:${clientId}` -> Set<id>
  private userIndex = new Map<string, Set<string>>(); // `${tenantId}:${userId}` -> Set<id>

  async create(input: CreateRefreshTokenInput): Promise<{ token: RefreshToken; value: string }> {
    const id = generateId();
    const tokenValue = generateRefreshToken();
    const tokenHash = hashToken(tokenValue);
    const familyId = input.familyId ?? generateFamilyId();
    const now = new Date();

    const token: RefreshToken = {
      id,
      tenantId: input.tenantId,
      clientId: input.clientId,
      userId: input.userId,
      tokenHash,
      scope: input.scope,
      expiresAt: input.expiresAt,
      issuedAt: now,
      parentTokenId: input.parentTokenId,
      familyId,
      metadata: input.metadata,
    };

    this.tokens.set(id, token);
    this.hashIndex.set(`${input.tenantId}:${tokenHash}`, id);

    // Update family index
    const familyKey = `${input.tenantId}:${familyId}`;
    if (!this.familyIndex.has(familyKey)) {
      this.familyIndex.set(familyKey, new Set());
    }
    this.familyIndex.get(familyKey)!.add(id);

    // Update user-client index
    if (input.userId) {
      const userClientKey = `${input.tenantId}:${input.userId}:${input.clientId}`;
      if (!this.userClientIndex.has(userClientKey)) {
        this.userClientIndex.set(userClientKey, new Set());
      }
      this.userClientIndex.get(userClientKey)!.add(id);

      // Update user index
      const userKey = `${input.tenantId}:${input.userId}`;
      if (!this.userIndex.has(userKey)) {
        this.userIndex.set(userKey, new Set());
      }
      this.userIndex.get(userKey)!.add(id);
    }

    return { token, value: tokenValue };
  }

  async findByHash(tenantId: string, tokenHash: string): Promise<RefreshToken | null> {
    const id = this.hashIndex.get(`${tenantId}:${tokenHash}`);
    if (!id) return null;
    return this.tokens.get(id) ?? null;
  }

  async findByValue(tenantId: string, tokenValue: string): Promise<RefreshToken | null> {
    const tokenHash = hashToken(tokenValue);
    return this.findByHash(tenantId, tokenHash);
  }

  async revoke(id: string): Promise<void> {
    const token = this.tokens.get(id);
    if (token && !token.revokedAt) {
      this.tokens.set(id, { ...token, revokedAt: new Date() });
    }
  }

  async revokeFamily(tenantId: string, familyId: string): Promise<number> {
    const familyKey = `${tenantId}:${familyId}`;
    const tokenIds = this.familyIndex.get(familyKey);
    if (!tokenIds) return 0;

    let count = 0;
    const now = new Date();
    for (const id of tokenIds) {
      const token = this.tokens.get(id);
      if (token && !token.revokedAt) {
        this.tokens.set(id, { ...token, revokedAt: now });
        count++;
      }
    }
    return count;
  }

  async revokeByUserAndClient(tenantId: string, userId: string, clientId: string): Promise<number> {
    const key = `${tenantId}:${userId}:${clientId}`;
    const tokenIds = this.userClientIndex.get(key);
    if (!tokenIds) return 0;

    let count = 0;
    const now = new Date();
    for (const id of tokenIds) {
      const token = this.tokens.get(id);
      if (token && !token.revokedAt) {
        this.tokens.set(id, { ...token, revokedAt: now });
        count++;
      }
    }
    return count;
  }

  async revokeByUser(tenantId: string, userId: string): Promise<number> {
    const key = `${tenantId}:${userId}`;
    const tokenIds = this.userIndex.get(key);
    if (!tokenIds) return 0;

    let count = 0;
    const now = new Date();
    for (const id of tokenIds) {
      const token = this.tokens.get(id);
      if (token && !token.revokedAt) {
        this.tokens.set(id, { ...token, revokedAt: now });
        count++;
      }
    }
    return count;
  }

  async isRevoked(id: string): Promise<boolean> {
    const token = this.tokens.get(id);
    return token?.revokedAt != null;
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const now = new Date();
    let deleted = 0;

    for (const [id, token] of this.tokens) {
      if (token.tenantId === tenantId && token.expiresAt < now) {
        this.hashIndex.delete(`${token.tenantId}:${token.tokenHash}`);

        const familyKey = `${token.tenantId}:${token.familyId}`;
        this.familyIndex.get(familyKey)?.delete(id);

        if (token.userId) {
          const userClientKey = `${token.tenantId}:${token.userId}:${token.clientId}`;
          this.userClientIndex.get(userClientKey)?.delete(id);

          const userKey = `${token.tenantId}:${token.userId}`;
          this.userIndex.get(userKey)?.delete(id);
        }

        this.tokens.delete(id);
        deleted++;
      }
    }

    return deleted;
  }
}

/**
 * In-memory revoked token storage implementation
 * For tracking revoked JWTs
 */
export class MemoryRevokedTokenStorage implements IRevokedTokenStorage {
  private revokedTokens = new Map<string, RevokedToken>();
  private tokenIdIndex = new Map<string, string>(); // `${tenantId}:${tokenId}` -> id

  async revoke(
    tenantId: string,
    tokenId: string,
    tokenType: 'access_token' | 'refresh_token',
    expiresAt: Date
  ): Promise<RevokedToken> {
    const id = generateId();
    const now = new Date();

    const revokedToken: RevokedToken = {
      id,
      tenantId,
      tokenId,
      tokenType,
      expiresAt,
      revokedAt: now,
    };

    this.revokedTokens.set(id, revokedToken);
    this.tokenIdIndex.set(`${tenantId}:${tokenId}`, id);

    return revokedToken;
  }

  async isRevoked(tenantId: string, tokenId: string): Promise<boolean> {
    return this.tokenIdIndex.has(`${tenantId}:${tokenId}`);
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const now = new Date();
    let deleted = 0;

    for (const [id, token] of this.revokedTokens) {
      if (token.tenantId === tenantId && token.expiresAt < now) {
        this.tokenIdIndex.delete(`${token.tenantId}:${token.tokenId}`);
        this.revokedTokens.delete(id);
        deleted++;
      }
    }

    return deleted;
  }
}
