import type { DeviceCode as PrismaDeviceCode } from '@prisma/client';
import type { DeviceCode, CreateDeviceCodeInput } from '../../../types/token.js';
import type { IDeviceCodeStorage } from '../../interfaces/device-code-storage.js';
import { getPrisma } from '../client.js';
import { generateDeviceCode, generateUserCode, hashToken } from '../../../crypto/index.js';

function prismaToDeviceCode(row: PrismaDeviceCode): DeviceCode {
  return {
    id: row.id,
    tenantId: row.tenantId,
    clientId: row.clientId,
    deviceCodeHash: row.deviceCodeHash,
    userCode: row.userCode,
    scope: row.scope ?? undefined,
    expiresAt: row.expiresAt,
    interval: row.interval,
    issuedAt: row.issuedAt,
    lastPolledAt: row.lastPolledAt ?? undefined,
    userId: row.userId ?? undefined,
    status: row.status as DeviceCode['status'],
  };
}

/**
 * Prisma device code storage implementation
 */
export class PrismaDeviceCodeStorage implements IDeviceCodeStorage {
  async create(input: CreateDeviceCodeInput): Promise<{
    deviceCode: DeviceCode;
    deviceCodeValue: string;
    userCode: string;
  }> {
    const prisma = getPrisma();
    const deviceCodeValue = generateDeviceCode();
    const deviceCodeHash = hashToken(deviceCodeValue);
    const userCode = generateUserCode();

    const row = await prisma.deviceCode.create({
      data: {
        tenantId: input.tenantId,
        clientId: input.clientId,
        deviceCodeHash,
        userCode,
        scope: input.scope,
        expiresAt: input.expiresAt,
        interval: input.interval,
        status: 'pending',
      },
    });

    return {
      deviceCode: prismaToDeviceCode(row),
      deviceCodeValue,
      userCode,
    };
  }

  async findByHash(tenantId: string, deviceCodeHash: string): Promise<DeviceCode | null> {
    const prisma = getPrisma();
    const row = await prisma.deviceCode.findUnique({
      where: { tenantId_deviceCodeHash: { tenantId, deviceCodeHash } },
    });
    return row ? prismaToDeviceCode(row) : null;
  }

  async findByValue(tenantId: string, deviceCodeValue: string): Promise<DeviceCode | null> {
    const deviceCodeHash = hashToken(deviceCodeValue);
    return this.findByHash(tenantId, deviceCodeHash);
  }

  async findByUserCode(tenantId: string, userCode: string): Promise<DeviceCode | null> {
    const prisma = getPrisma();
    const normalizedCode = userCode.replace(/-/g, '').toUpperCase();
    const withDash = normalizedCode.slice(0, 4) + '-' + normalizedCode.slice(4);

    const row = await prisma.deviceCode.findUnique({
      where: { tenantId_userCode: { tenantId, userCode: withDash } },
    });
    return row ? prismaToDeviceCode(row) : null;
  }

  async updateLastPolled(id: string): Promise<boolean> {
    const prisma = getPrisma();

    const result = await prisma.$transaction(async (tx) => {
      const code = await tx.deviceCode.findUnique({ where: { id } });
      if (!code) return false;

      const now = new Date();
      if (code.lastPolledAt) {
        const timeSinceLastPoll = now.getTime() - code.lastPolledAt.getTime();
        if (timeSinceLastPoll < code.interval * 1000) {
          return false;
        }
      }

      await tx.deviceCode.update({
        where: { id },
        data: { lastPolledAt: now },
      });

      return true;
    });

    return result;
  }

  async authorize(id: string, userId: string): Promise<DeviceCode> {
    const prisma = getPrisma();
    const row = await prisma.deviceCode.update({
      where: { id },
      data: { userId, status: 'authorized' },
    });
    return prismaToDeviceCode(row);
  }

  async deny(id: string): Promise<DeviceCode> {
    const prisma = getPrisma();
    const row = await prisma.deviceCode.update({
      where: { id },
      data: { status: 'denied' },
    });
    return prismaToDeviceCode(row);
  }

  async consume(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.deviceCode.delete({ where: { id } });
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const prisma = getPrisma();
    const result = await prisma.deviceCode.deleteMany({
      where: { tenantId, expiresAt: { lt: new Date() } },
    });
    return result.count;
  }
}
