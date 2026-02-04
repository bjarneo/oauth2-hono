import type { FederatedIdentity as PrismaFederatedIdentity } from '@prisma/client';
import type {
  FederatedIdentity,
  CreateFederatedIdentityInput,
  UpdateFederatedIdentityInput,
  IFederatedIdentityStorage,
} from '../../interfaces/federated-identity-storage.js';
import { getPrisma } from '../client.js';

function prismaToFederatedIdentity(row: PrismaFederatedIdentity): FederatedIdentity {
  return {
    id: row.id,
    tenantId: row.tenantId,
    userId: row.userId,
    providerId: row.providerId,
    providerUserId: row.providerUserId,
    providerUserData: row.providerUserData as Record<string, unknown> | undefined,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/**
 * Prisma federated identity storage implementation
 */
export class PrismaFederatedIdentityStorage implements IFederatedIdentityStorage {
  async create(input: CreateFederatedIdentityInput): Promise<FederatedIdentity> {
    const prisma = getPrisma();

    const row = await prisma.federatedIdentity.create({
      data: {
        tenantId: input.tenantId,
        userId: input.userId,
        providerId: input.providerId,
        providerUserId: input.providerUserId,
        providerUserData: input.providerUserData as unknown as Parameters<typeof prisma.federatedIdentity.create>[0]['data']['providerUserData'],
      },
    });

    return prismaToFederatedIdentity(row);
  }

  async findById(id: string): Promise<FederatedIdentity | null> {
    const prisma = getPrisma();
    const row = await prisma.federatedIdentity.findUnique({ where: { id } });
    return row ? prismaToFederatedIdentity(row) : null;
  }

  async findByProviderIdentity(
    tenantId: string,
    providerId: string,
    providerUserId: string
  ): Promise<FederatedIdentity | null> {
    const prisma = getPrisma();
    const row = await prisma.federatedIdentity.findUnique({
      where: {
        tenantId_providerId_providerUserId: {
          tenantId,
          providerId,
          providerUserId,
        },
      },
    });
    return row ? prismaToFederatedIdentity(row) : null;
  }

  async findByUser(tenantId: string, userId: string): Promise<FederatedIdentity[]> {
    const prisma = getPrisma();
    const rows = await prisma.federatedIdentity.findMany({
      where: { tenantId, userId },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map(prismaToFederatedIdentity);
  }

  async update(id: string, input: UpdateFederatedIdentityInput): Promise<FederatedIdentity> {
    const prisma = getPrisma();

    const row = await prisma.federatedIdentity.update({
      where: { id },
      data: {
        providerUserData: input.providerUserData as unknown as Parameters<typeof prisma.federatedIdentity.update>[0]['data']['providerUserData'],
      },
    });

    return prismaToFederatedIdentity(row);
  }

  async delete(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.federatedIdentity.delete({ where: { id } });
  }

  async deleteByUser(tenantId: string, userId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.federatedIdentity.deleteMany({
      where: { tenantId, userId },
    });
    return result.count;
  }

  async deleteByProvider(tenantId: string, providerId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.federatedIdentity.deleteMany({
      where: { tenantId, providerId },
    });
    return result.count;
  }
}
