import type { RefreshToken as PrismaRefreshToken, RevokedToken as PrismaRevokedToken } from '@prisma/client';
import type { RefreshToken, CreateRefreshTokenInput, RevokedToken } from '../../../types/token.js';
import type { IRefreshTokenStorage, IRevokedTokenStorage } from '../../interfaces/token-storage.js';
import { getPrisma } from '../client.js';
import { generateRefreshToken, generateFamilyId, hashToken } from '../../../crypto/index.js';

function prismaToRefreshToken(row: PrismaRefreshToken): RefreshToken {
  return {
    id: row.id,
    tenantId: row.tenantId,
    clientId: row.clientId,
    userId: row.userId ?? undefined,
    tokenHash: row.tokenHash,
    scope: row.scope ?? undefined,
    expiresAt: row.expiresAt,
    issuedAt: row.issuedAt,
    revokedAt: row.revokedAt ?? undefined,
    parentTokenId: row.parentTokenId ?? undefined,
    familyId: row.familyId,
    metadata: row.metadata as Record<string, unknown> | undefined,
  };
}

function prismaToRevokedToken(row: PrismaRevokedToken): RevokedToken {
  return {
    id: row.id,
    tenantId: row.tenantId,
    tokenId: row.tokenId,
    tokenType: row.tokenType as 'access_token' | 'refresh_token',
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
  };
}

/**
 * Prisma refresh token storage implementation
 */
export class PrismaRefreshTokenStorage implements IRefreshTokenStorage {
  async create(input: CreateRefreshTokenInput): Promise<{ token: RefreshToken; value: string }> {
    const prisma = getPrisma();
    const tokenValue = generateRefreshToken();
    const tokenHash = hashToken(tokenValue);
    const familyId = input.familyId ?? generateFamilyId();

    const row = await prisma.refreshToken.create({
      data: {
        tenantId: input.tenantId,
        clientId: input.clientId,
        userId: input.userId,
        tokenHash,
        scope: input.scope,
        expiresAt: input.expiresAt,
        parentTokenId: input.parentTokenId,
        familyId,
        metadata: input.metadata ?? undefined,
      },
    });

    return { token: prismaToRefreshToken(row), value: tokenValue };
  }

  async findByHash(tenantId: string, tokenHash: string): Promise<RefreshToken | null> {
    const prisma = getPrisma();
    const row = await prisma.refreshToken.findUnique({
      where: { tenantId_tokenHash: { tenantId, tokenHash } },
    });
    return row ? prismaToRefreshToken(row) : null;
  }

  async findByValue(tenantId: string, tokenValue: string): Promise<RefreshToken | null> {
    const tokenHash = hashToken(tokenValue);
    return this.findByHash(tenantId, tokenHash);
  }

  async revoke(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.refreshToken.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
  }

  async revokeFamily(tenantId: string, familyId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.refreshToken.updateMany({
      where: { tenantId, familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return result.count;
  }

  async revokeByUserAndClient(tenantId: string, userId: string, clientId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.refreshToken.updateMany({
      where: { tenantId, userId, clientId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return result.count;
  }

  async revokeByUser(tenantId: string, userId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.refreshToken.updateMany({
      where: { tenantId, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return result.count;
  }

  async isRevoked(id: string): Promise<boolean> {
    const prisma = getPrisma();
    const row = await prisma.refreshToken.findUnique({
      where: { id },
      select: { revokedAt: true },
    });
    return row?.revokedAt != null;
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.refreshToken.deleteMany({
      where: { tenantId, expiresAt: { lt: new Date() } },
    });
    return result.count;
  }
}

/**
 * Prisma revoked token storage implementation
 */
export class PrismaRevokedTokenStorage implements IRevokedTokenStorage {
  async revoke(
    tenantId: string,
    tokenId: string,
    tokenType: 'access_token' | 'refresh_token',
    expiresAt: Date
  ): Promise<RevokedToken> {
    const prisma = getPrisma();

    const row = await prisma.revokedToken.upsert({
      where: { tenantId_tokenId: { tenantId, tokenId } },
      update: {},
      create: { tenantId, tokenId, tokenType, expiresAt },
    });

    return prismaToRevokedToken(row);
  }

  async isRevoked(tenantId: string, tokenId: string): Promise<boolean> {
    const prisma = getPrisma();
    const count = await prisma.revokedToken.count({
      where: { tenantId, tokenId },
    });
    return count > 0;
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.revokedToken.deleteMany({
      where: { tenantId, expiresAt: { lt: new Date() } },
    });
    return result.count;
  }
}
