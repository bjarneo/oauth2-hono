import type { AuthorizationCode as PrismaAuthorizationCode } from '@prisma/client';
import type { AuthorizationCode, CreateAuthorizationCodeInput } from '../../../types/token.js';
import type { IAuthorizationCodeStorage } from '../../interfaces/authorization-code-storage.js';
import { getPrisma } from '../client.js';
import { generateAuthorizationCode, hashToken } from '../../../crypto/index.js';

function prismaToAuthorizationCode(row: PrismaAuthorizationCode): AuthorizationCode {
  return {
    id: row.id,
    tenantId: row.tenantId,
    clientId: row.clientId,
    userId: row.userId,
    codeHash: row.codeHash,
    redirectUri: row.redirectUri,
    scope: row.scope ?? undefined,
    codeChallenge: row.codeChallenge,
    codeChallengeMethod: row.codeChallengeMethod as 'S256',
    nonce: row.nonce ?? undefined,
    state: row.state ?? undefined,
    expiresAt: row.expiresAt,
    issuedAt: row.issuedAt,
    usedAt: row.usedAt ?? undefined,
  };
}

/**
 * Prisma authorization code storage implementation
 */
export class PrismaAuthorizationCodeStorage implements IAuthorizationCodeStorage {
  async create(input: CreateAuthorizationCodeInput): Promise<{ code: AuthorizationCode; value: string }> {
    const prisma = getPrisma();
    const codeValue = generateAuthorizationCode();
    const codeHash = hashToken(codeValue);

    const row = await prisma.authorizationCode.create({
      data: {
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
      },
    });

    return { code: prismaToAuthorizationCode(row), value: codeValue };
  }

  async findByHash(tenantId: string, codeHash: string): Promise<AuthorizationCode | null> {
    const prisma = getPrisma();
    const row = await prisma.authorizationCode.findUnique({
      where: { tenantId_codeHash: { tenantId, codeHash } },
    });
    return row ? prismaToAuthorizationCode(row) : null;
  }

  async findByValue(tenantId: string, codeValue: string): Promise<AuthorizationCode | null> {
    const codeHash = hashToken(codeValue);
    return this.findByHash(tenantId, codeHash);
  }

  async consume(tenantId: string, codeValue: string): Promise<AuthorizationCode | null> {
    const prisma = getPrisma();
    const codeHash = hashToken(codeValue);

    // Use a transaction to ensure atomicity
    const result = await prisma.$transaction(async (tx) => {
      const code = await tx.authorizationCode.findUnique({
        where: { tenantId_codeHash: { tenantId, codeHash } },
      });

      if (!code) return null;
      if (code.usedAt) return null;
      if (code.expiresAt < new Date()) return null;

      const updated = await tx.authorizationCode.update({
        where: { id: code.id },
        data: { usedAt: new Date() },
      });

      return updated;
    });

    return result ? prismaToAuthorizationCode(result) : null;
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.authorizationCode.deleteMany({
      where: { tenantId, expiresAt: { lt: new Date() } },
    });
    return result.count;
  }
}
