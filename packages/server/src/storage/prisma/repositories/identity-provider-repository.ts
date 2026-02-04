import type { IdentityProvider as PrismaIdentityProvider } from '@prisma/client';
import type {
  IdentityProvider,
  IdentityProviderType,
  IdentityProviderTemplate,
  AttributeMapping,
  CreateIdentityProviderInput,
  UpdateIdentityProviderInput,
  IIdentityProviderStorage,
} from '../../interfaces/identity-provider-storage.js';
import { getPrisma } from '../client.js';
import { encrypt } from '../../../crypto/encrypt.js';

function prismaToIdentityProvider(row: PrismaIdentityProvider): IdentityProvider {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    slug: row.slug,
    type: row.type as IdentityProviderType,
    template: row.template as IdentityProviderTemplate | undefined,
    clientId: row.clientId,
    clientSecretEncrypted: row.clientSecretEncrypted,
    issuer: row.issuer ?? undefined,
    authorizationEndpoint: row.authorizationEndpoint ?? undefined,
    tokenEndpoint: row.tokenEndpoint ?? undefined,
    userinfoEndpoint: row.userinfoEndpoint ?? undefined,
    jwksUri: row.jwksUri ?? undefined,
    scopes: row.scopes,
    attributeMapping: row.attributeMapping as AttributeMapping | undefined,
    enabled: row.enabled,
    displayOrder: row.displayOrder ?? undefined,
    iconUrl: row.iconUrl ?? undefined,
    buttonText: row.buttonText ?? undefined,
    metadata: row.metadata as Record<string, unknown> | undefined,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/**
 * Prisma identity provider storage implementation
 */
export class PrismaIdentityProviderStorage implements IIdentityProviderStorage {
  async create(input: CreateIdentityProviderInput): Promise<IdentityProvider> {
    const prisma = getPrisma();

    // Encrypt the client secret
    const clientSecretEncrypted = encrypt(input.clientSecret);

    const row = await prisma.identityProvider.create({
      data: {
        tenantId: input.tenantId,
        name: input.name,
        slug: input.slug,
        type: input.type ?? 'oidc',
        template: input.template,
        clientId: input.clientId,
        clientSecretEncrypted,
        issuer: input.issuer,
        authorizationEndpoint: input.authorizationEndpoint,
        tokenEndpoint: input.tokenEndpoint,
        userinfoEndpoint: input.userinfoEndpoint,
        jwksUri: input.jwksUri,
        scopes: input.scopes ?? ['openid', 'profile', 'email'],
        attributeMapping: input.attributeMapping as unknown as Parameters<typeof prisma.identityProvider.create>[0]['data']['attributeMapping'],
        enabled: input.enabled ?? true,
        displayOrder: input.displayOrder,
        iconUrl: input.iconUrl,
        buttonText: input.buttonText,
        metadata: input.metadata as unknown as Parameters<typeof prisma.identityProvider.create>[0]['data']['metadata'],
      },
    });

    return prismaToIdentityProvider(row);
  }

  async findById(id: string): Promise<IdentityProvider | null> {
    const prisma = getPrisma();
    const row = await prisma.identityProvider.findUnique({ where: { id } });
    return row ? prismaToIdentityProvider(row) : null;
  }

  async findBySlug(tenantId: string, slug: string): Promise<IdentityProvider | null> {
    const prisma = getPrisma();
    const row = await prisma.identityProvider.findUnique({
      where: { tenantId_slug: { tenantId, slug } },
    });
    return row ? prismaToIdentityProvider(row) : null;
  }

  async update(id: string, input: UpdateIdentityProviderInput): Promise<IdentityProvider> {
    const prisma = getPrisma();

    // If client secret is being updated, encrypt it
    let clientSecretEncrypted: string | undefined;
    if (input.clientSecret) {
      clientSecretEncrypted = encrypt(input.clientSecret);
    }

    const row = await prisma.identityProvider.update({
      where: { id },
      data: {
        name: input.name,
        clientId: input.clientId,
        clientSecretEncrypted,
        issuer: input.issuer,
        authorizationEndpoint: input.authorizationEndpoint,
        tokenEndpoint: input.tokenEndpoint,
        userinfoEndpoint: input.userinfoEndpoint,
        jwksUri: input.jwksUri,
        scopes: input.scopes,
        attributeMapping: input.attributeMapping as unknown as Parameters<typeof prisma.identityProvider.update>[0]['data']['attributeMapping'],
        enabled: input.enabled,
        displayOrder: input.displayOrder,
        iconUrl: input.iconUrl,
        buttonText: input.buttonText,
        metadata: input.metadata as unknown as Parameters<typeof prisma.identityProvider.update>[0]['data']['metadata'],
      },
    });

    return prismaToIdentityProvider(row);
  }

  async delete(id: string): Promise<void> {
    const prisma = getPrisma();
    await prisma.identityProvider.delete({ where: { id } });
  }

  async listByTenant(tenantId: string): Promise<IdentityProvider[]> {
    const prisma = getPrisma();

    const rows = await prisma.identityProvider.findMany({
      where: { tenantId },
      orderBy: [{ displayOrder: 'asc' }, { createdAt: 'asc' }],
    });

    return rows.map(prismaToIdentityProvider);
  }

  async listEnabledByTenant(tenantId: string): Promise<IdentityProvider[]> {
    const prisma = getPrisma();

    const rows = await prisma.identityProvider.findMany({
      where: { tenantId, enabled: true },
      orderBy: [{ displayOrder: 'asc' }, { createdAt: 'asc' }],
    });

    return rows.map(prismaToIdentityProvider);
  }
}
