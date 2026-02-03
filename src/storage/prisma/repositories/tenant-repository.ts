import type { Tenant as PrismaTenant, SigningKey as PrismaSigningKey } from '@prisma/client';
import type { Tenant, CreateTenantInput, UpdateTenantInput, SigningKey, CreateSigningKeyInput } from '../../../types/tenant.js';
import type { GrantType } from '../../../types/oauth.js';
import type { ITenantStorage, ISigningKeyStorage } from '../../interfaces/tenant-storage.js';
import { getPrisma } from '../client.js';
import { generateKid, generateRsaKeyPair, generateEcKeyPair } from '../../../crypto/index.js';
import { getConfig } from '../../../config/index.js';
import {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  GRANT_TYPE_DEVICE_CODE,
} from '../../../config/constants.js';

function prismaToTenant(row: PrismaTenant): Tenant {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    issuer: row.issuer,
    allowedGrants: row.allowedGrants as GrantType[],
    allowedScopes: row.allowedScopes,
    accessTokenTtl: row.accessTokenTtl,
    refreshTokenTtl: row.refreshTokenTtl,
    authorizationCodeTtl: row.authorizationCodeTtl,
    deviceCodeTtl: row.deviceCodeTtl,
    deviceCodeInterval: row.deviceCodeInterval,
    requirePkce: row.requirePkce,
    allowedRedirectUriPatterns: row.allowedRedirectUriPatterns.length > 0 ? row.allowedRedirectUriPatterns : undefined,
    metadata: row.metadata as Record<string, unknown> | undefined,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function prismaToSigningKey(row: PrismaSigningKey): SigningKey {
  return {
    id: row.id,
    tenantId: row.tenantId,
    kid: row.kid,
    algorithm: row.algorithm as SigningKey['algorithm'],
    publicKey: row.publicKey,
    privateKey: row.privateKey,
    isPrimary: row.isPrimary,
    expiresAt: row.expiresAt ?? undefined,
    createdAt: row.createdAt,
  };
}

/**
 * Prisma tenant storage implementation
 */
export class PrismaTenantStorage implements ITenantStorage {
  async create(input: CreateTenantInput): Promise<Tenant> {
    const prisma = getPrisma();
    const config = getConfig();

    const row = await prisma.tenant.create({
      data: {
        name: input.name,
        slug: input.slug,
        issuer: input.issuer ?? `http://localhost:${config.server.port}/${input.slug}`,
        allowedGrants: input.allowedGrants ?? [
          GRANT_TYPE_AUTHORIZATION_CODE,
          GRANT_TYPE_CLIENT_CREDENTIALS,
          GRANT_TYPE_REFRESH_TOKEN,
          GRANT_TYPE_DEVICE_CODE,
        ],
        allowedScopes: input.allowedScopes ?? ['openid', 'profile', 'email', 'offline_access'],
        accessTokenTtl: input.accessTokenTtl ?? config.defaults.accessTokenTtl,
        refreshTokenTtl: input.refreshTokenTtl ?? config.defaults.refreshTokenTtl,
        authorizationCodeTtl: input.authorizationCodeTtl ?? config.defaults.authorizationCodeTtl,
        deviceCodeTtl: input.deviceCodeTtl ?? config.defaults.deviceCodeTtl,
        deviceCodeInterval: input.deviceCodeInterval ?? config.defaults.deviceCodeInterval,
        requirePkce: true,
        allowedRedirectUriPatterns: input.allowedRedirectUriPatterns ?? [],
        metadata: input.metadata ?? undefined,
      },
    });

    return prismaToTenant(row);
  }

  async findById(id: string): Promise<Tenant | null> {
    const prisma = getPrisma();
    const row = await prisma.tenant.findUnique({ where: { id } });
    return row ? prismaToTenant(row) : null;
  }

  async findBySlug(slug: string): Promise<Tenant | null> {
    const prisma = getPrisma();
    const row = await prisma.tenant.findUnique({ where: { slug } });
    return row ? prismaToTenant(row) : null;
  }

  async update(id: string, input: UpdateTenantInput): Promise<Tenant> {
    const prisma = getPrisma();

    const row = await prisma.tenant.update({
      where: { id },
      data: {
        name: input.name,
        issuer: input.issuer,
        allowedGrants: input.allowedGrants,
        allowedScopes: input.allowedScopes,
        accessTokenTtl: input.accessTokenTtl,
        refreshTokenTtl: input.refreshTokenTtl,
        authorizationCodeTtl: input.authorizationCodeTtl,
        deviceCodeTtl: input.deviceCodeTtl,
        deviceCodeInterval: input.deviceCodeInterval,
        allowedRedirectUriPatterns: input.allowedRedirectUriPatterns,
        metadata: input.metadata ?? undefined,
      },
    });

    return prismaToTenant(row);
  }

  async delete(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.tenant.delete({ where: { id } });
  }

  async list(options?: { limit?: number; offset?: number }): Promise<Tenant[]> {
    const prisma = getPrisma();

    const rows = await prisma.tenant.findMany({
      take: options?.limit ?? 100,
      skip: options?.offset ?? 0,
      orderBy: { createdAt: 'desc' },
    });

    return rows.map(prismaToTenant);
  }
}

/**
 * Prisma signing key storage implementation
 */
export class PrismaSigningKeyStorage implements ISigningKeyStorage {
  async create(input: CreateSigningKeyInput): Promise<SigningKey> {
    const prisma = getPrisma();
    const kid = generateKid();
    const algorithm = input.algorithm ?? 'RS256';

    let keyPair: { publicKey: string; privateKey: string };
    if (algorithm.startsWith('RS')) {
      keyPair = await generateRsaKeyPair(algorithm as 'RS256' | 'RS384' | 'RS512');
    } else {
      keyPair = await generateEcKeyPair(algorithm as 'ES256' | 'ES384' | 'ES512');
    }

    if (input.isPrimary) {
      await prisma.signingKey.updateMany({
        where: { tenantId: input.tenantId, isPrimary: true },
        data: { isPrimary: false },
      });
    }

    const row = await prisma.signingKey.create({
      data: {
        tenantId: input.tenantId,
        kid,
        algorithm,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        isPrimary: input.isPrimary ?? false,
        expiresAt: input.expiresAt,
      },
    });

    return prismaToSigningKey(row);
  }

  async findById(id: string): Promise<SigningKey | null> {
    const prisma = getPrisma();
    const row = await prisma.signingKey.findUnique({ where: { id } });
    return row ? prismaToSigningKey(row) : null;
  }

  async findByKid(tenantId: string, kid: string): Promise<SigningKey | null> {
    const prisma = getPrisma();
    const row = await prisma.signingKey.findUnique({
      where: { tenantId_kid: { tenantId, kid } },
    });
    return row ? prismaToSigningKey(row) : null;
  }

  async getPrimary(tenantId: string): Promise<SigningKey | null> {
    const prisma = getPrisma();
    const row = await prisma.signingKey.findFirst({
      where: { tenantId, isPrimary: true },
    });
    return row ? prismaToSigningKey(row) : null;
  }

  async listByTenant(tenantId: string): Promise<SigningKey[]> {
    const prisma = getPrisma();
    const rows = await prisma.signingKey.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(prismaToSigningKey);
  }

  async setPrimary(id: string): Promise<SigningKey> {
    const prisma = getPrisma();

    const key = await prisma.signingKey.findUnique({ where: { id } });
    if (!key) {
      throw new Error(`Signing key not found: ${id}`);
    }

    await prisma.signingKey.updateMany({
      where: { tenantId: key.tenantId, isPrimary: true, id: { not: id } },
      data: { isPrimary: false },
    });

    const row = await prisma.signingKey.update({
      where: { id },
      data: { isPrimary: true },
    });

    return prismaToSigningKey(row);
  }

  async delete(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.signingKey.delete({ where: { id } });
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.signingKey.deleteMany({
      where: {
        tenantId,
        expiresAt: { not: null, lt: new Date() },
      },
    });
    return result.count;
  }
}
