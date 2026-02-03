import { PrismaClient } from '@prisma/client';

let prisma: PrismaClient | null = null;

/**
 * Initialize the Prisma client
 */
export function initializePrisma(): PrismaClient {
  if (prisma) {
    return prisma;
  }

  prisma = new PrismaClient({
    log: process.env['NODE_ENV'] === 'development' ? ['error', 'warn'] : ['error'],
  });

  return prisma;
}

/**
 * Get the current Prisma client
 * Throws if not initialized
 */
export function getPrisma(): PrismaClient {
  if (!prisma) {
    prisma = initializePrisma();
  }
  return prisma;
}

/**
 * Close the Prisma connection
 */
export async function closePrisma(): Promise<void> {
  if (prisma) {
    await prisma.$disconnect();
    prisma = null;
  }
}
