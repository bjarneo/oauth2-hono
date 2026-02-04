import type { Client as PrismaClient } from '@prisma/client';
import type { OAuthClient, CreateClientInput, UpdateClientInput, ClientType, ClientAuthMethod, JsonWebKeySet } from '../../../types/client.js';
import type { GrantType } from '../../../types/oauth.js';
import type { IClientStorage } from '../../interfaces/client-storage.js';
import { getPrisma } from '../client.js';
import {
  generateClientId,
  generateClientSecret,
  hashClientSecret,
  verifyClientSecret,
} from '../../../crypto/index.js';

function prismaToClient(row: PrismaClient): OAuthClient {
  return {
    id: row.id,
    tenantId: row.tenantId,
    clientId: row.clientId,
    clientSecretHash: row.clientSecretHash ?? undefined,
    clientType: row.clientType as ClientType,
    authMethod: row.authMethod as ClientAuthMethod,
    name: row.name,
    description: row.description ?? undefined,
    redirectUris: row.redirectUris,
    allowedGrants: row.allowedGrants as GrantType[],
    allowedScopes: row.allowedScopes,
    defaultScopes: row.defaultScopes.length > 0 ? row.defaultScopes : undefined,
    jwksUri: row.jwksUri ?? undefined,
    jwks: row.jwks as unknown as JsonWebKeySet | undefined,
    accessTokenTtl: row.accessTokenTtl ?? undefined,
    refreshTokenTtl: row.refreshTokenTtl ?? undefined,
    requireConsent: row.requireConsent,
    firstParty: row.firstParty,
    metadata: row.metadata as Record<string, unknown> | undefined,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/**
 * Prisma OAuth client storage implementation
 */
export class PrismaClientStorage implements IClientStorage {
  async create(input: CreateClientInput): Promise<{ client: OAuthClient; clientSecret?: string }> {
    const prisma = getPrisma();
    const clientId = generateClientId();

    let clientSecretHash: string | null = null;
    let clientSecret: string | undefined;

    if (input.clientType === 'confidential' && input.authMethod !== 'private_key_jwt') {
      clientSecret = generateClientSecret();
      clientSecretHash = await hashClientSecret(clientSecret);
    }

    const row = await prisma.client.create({
      data: {
        tenantId: input.tenantId,
        clientId,
        clientSecretHash,
        clientType: input.clientType,
        authMethod: input.authMethod,
        name: input.name,
        description: input.description,
        redirectUris: input.redirectUris,
        allowedGrants: input.allowedGrants,
        allowedScopes: input.allowedScopes,
        defaultScopes: input.defaultScopes ?? [],
        jwksUri: input.jwksUri,
        jwks: input.jwks as unknown as Parameters<typeof prisma.client.create>[0]['data']['jwks'],
        accessTokenTtl: input.accessTokenTtl,
        refreshTokenTtl: input.refreshTokenTtl,
        requireConsent: input.requireConsent ?? true,
        firstParty: input.firstParty ?? false,
        metadata: input.metadata as unknown as Parameters<typeof prisma.client.create>[0]['data']['metadata'],
      },
    });

    return { client: prismaToClient(row), clientSecret };
  }

  async findById(id: string): Promise<OAuthClient | null> {
    const prisma = getPrisma();
    const row = await prisma.client.findUnique({ where: { id } });
    return row ? prismaToClient(row) : null;
  }

  async findByClientId(tenantId: string, clientId: string): Promise<OAuthClient | null> {
    const prisma = getPrisma();
    const row = await prisma.client.findUnique({
      where: { tenantId_clientId: { tenantId, clientId } },
    });
    return row ? prismaToClient(row) : null;
  }

  async update(id: string, input: UpdateClientInput): Promise<OAuthClient> {
    const prisma = getPrisma();

    const row = await prisma.client.update({
      where: { id },
      data: {
        name: input.name,
        description: input.description,
        redirectUris: input.redirectUris,
        allowedGrants: input.allowedGrants,
        allowedScopes: input.allowedScopes,
        defaultScopes: input.defaultScopes,
        jwksUri: input.jwksUri,
        jwks: input.jwks as unknown as Parameters<typeof prisma.client.update>[0]['data']['jwks'],
        accessTokenTtl: input.accessTokenTtl,
        refreshTokenTtl: input.refreshTokenTtl,
        requireConsent: input.requireConsent,
        firstParty: input.firstParty,
        metadata: input.metadata as unknown as Parameters<typeof prisma.client.update>[0]['data']['metadata'],
      },
    });

    return prismaToClient(row);
  }

  async regenerateSecret(id: string): Promise<string> {
    const prisma = getPrisma();

    const client = await prisma.client.findUnique({ where: { id } });
    if (!client) {
      throw new Error(`Client not found: ${id}`);
    }

    if (client.clientType !== 'confidential') {
      throw new Error('Cannot generate secret for public client');
    }

    const newSecret = generateClientSecret();
    const newHash = await hashClientSecret(newSecret);

    await prisma.client.update({
      where: { id },
      data: { clientSecretHash: newHash },
    });

    return newSecret;
  }

  async delete(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.client.delete({ where: { id } });
  }

  async listByTenant(
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<OAuthClient[]> {
    const prisma = getPrisma();

    const rows = await prisma.client.findMany({
      where: { tenantId },
      take: options?.limit ?? 100,
      skip: options?.offset ?? 0,
      orderBy: { createdAt: 'desc' },
    });

    return rows.map(prismaToClient);
  }

  async verifyCredentials(
    tenantId: string,
    clientId: string,
    clientSecret: string
  ): Promise<OAuthClient | null> {
    const client = await this.findByClientId(tenantId, clientId);
    if (!client) return null;

    if (!client.clientSecretHash) {
      return null;
    }

    const isValid = await verifyClientSecret(clientSecret, client.clientSecretHash);
    return isValid ? client : null;
  }
}
