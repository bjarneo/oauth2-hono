import { PrismaClient } from '@prisma/client';
import { generateRsaKeyPair } from '../src/crypto/jwt.js';
import { generateClientId, generateClientSecret, generateKid } from '../src/crypto/random.js';
import { hashClientSecret } from '../src/crypto/hash.js';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...\n');

  // Create development tenant
  const devTenant = await prisma.tenant.upsert({
    where: { slug: 'dev' },
    update: {},
    create: {
      name: 'Development Tenant',
      slug: 'dev',
      issuer: 'http://localhost:3000/dev',
      allowedGrants: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
      accessTokenTtl: 3600,
      refreshTokenTtl: 2592000,
      authorizationCodeTtl: 600,
      deviceCodeTtl: 1800,
      deviceCodeInterval: 5,
    },
  });
  console.log(`Created tenant: ${devTenant.name} (slug: ${devTenant.slug})`);

  // Create demo tenant
  const demoTenant = await prisma.tenant.upsert({
    where: { slug: 'demo' },
    update: {},
    create: {
      name: 'Demo Tenant',
      slug: 'demo',
      issuer: 'http://localhost:3000/demo',
      allowedGrants: ['authorization_code', 'refresh_token'],
      allowedScopes: ['openid', 'profile', 'email'],
      accessTokenTtl: 1800,
      refreshTokenTtl: 604800,
    },
  });
  console.log(`Created tenant: ${demoTenant.name} (slug: ${demoTenant.slug})`);

  // Create signing keys for each tenant
  for (const tenant of [devTenant, demoTenant]) {
    const existingKey = await prisma.signingKey.findFirst({
      where: { tenantId: tenant.id, isPrimary: true },
    });

    if (!existingKey) {
      const keyPair = await generateRsaKeyPair('RS256');
      const signingKey = await prisma.signingKey.create({
        data: {
          tenantId: tenant.id,
          kid: generateKid(),
          algorithm: 'RS256',
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          isPrimary: true,
        },
      });
      console.log(`Created signing key for ${tenant.slug}: ${signingKey.kid}`);
    }
  }

  // Create confidential client for dev tenant
  const confidentialClientId = generateClientId();
  const confidentialClientSecret = generateClientSecret();
  const confidentialSecretHash = await hashClientSecret(confidentialClientSecret);

  const existingConfidentialClient = await prisma.client.findFirst({
    where: { tenantId: devTenant.id, name: 'Development Backend' },
  });

  if (!existingConfidentialClient) {
    const confidentialClient = await prisma.client.create({
      data: {
        tenantId: devTenant.id,
        clientId: confidentialClientId,
        clientSecretHash: confidentialSecretHash,
        clientType: 'confidential',
        authMethod: 'client_secret_basic',
        name: 'Development Backend',
        description: 'Backend application for development and testing',
        redirectUris: [
          'http://localhost:3001/callback',
          'http://localhost:8080/callback',
          'http://127.0.0.1:3001/callback',
        ],
        allowedGrants: [
          'authorization_code',
          'client_credentials',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:device_code',
        ],
        allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
        defaultScopes: ['openid', 'profile'],
        requireConsent: false,
        firstParty: true,
      },
    });

    console.log(`\nCreated confidential client: ${confidentialClient.name}`);
    console.log(`  Client ID: ${confidentialClient.clientId}`);
    console.log(`  Client Secret: ${confidentialClientSecret}`);
  }

  // Create public client (SPA) for dev tenant
  const publicClientId = generateClientId();

  const existingPublicClient = await prisma.client.findFirst({
    where: { tenantId: devTenant.id, name: 'Development SPA' },
  });

  if (!existingPublicClient) {
    const publicClient = await prisma.client.create({
      data: {
        tenantId: devTenant.id,
        clientId: publicClientId,
        clientType: 'public',
        authMethod: 'none',
        name: 'Development SPA',
        description: 'Single page application for development',
        redirectUris: [
          'http://localhost:3001/callback',
          'http://localhost:5173/callback',
          'http://127.0.0.1:5173/callback',
        ],
        allowedGrants: ['authorization_code', 'refresh_token'],
        allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        defaultScopes: ['openid', 'profile'],
        requireConsent: true,
        firstParty: false,
      },
    });

    console.log(`\nCreated public client: ${publicClient.name}`);
    console.log(`  Client ID: ${publicClient.clientId}`);
  }

  // Create client for demo tenant
  const demoClientId = generateClientId();
  const demoClientSecret = generateClientSecret();
  const demoSecretHash = await hashClientSecret(demoClientSecret);

  const existingDemoClient = await prisma.client.findFirst({
    where: { tenantId: demoTenant.id, name: 'Demo Application' },
  });

  if (!existingDemoClient) {
    const demoClient = await prisma.client.create({
      data: {
        tenantId: demoTenant.id,
        clientId: demoClientId,
        clientSecretHash: demoSecretHash,
        clientType: 'confidential',
        authMethod: 'client_secret_post',
        name: 'Demo Application',
        description: 'Demo application for testing',
        redirectUris: ['http://localhost:4000/callback'],
        allowedGrants: ['authorization_code', 'refresh_token'],
        allowedScopes: ['openid', 'profile', 'email'],
        defaultScopes: ['openid'],
        requireConsent: true,
      },
    });

    console.log(`\nCreated demo client: ${demoClient.name}`);
    console.log(`  Client ID: ${demoClient.clientId}`);
    console.log(`  Client Secret: ${demoClientSecret}`);
  }

  console.log('\n========================================');
  console.log('Seed completed successfully');
  console.log('========================================\n');

  // Print summary of all clients
  const allClients = await prisma.client.findMany({
    include: { tenant: true },
  });

  console.log('Available clients:\n');
  for (const client of allClients) {
    console.log(`Tenant: ${client.tenant.slug}`);
    console.log(`  Name: ${client.name}`);
    console.log(`  Client ID: ${client.clientId}`);
    console.log(`  Type: ${client.clientType}`);
    console.log(`  Auth Method: ${client.authMethod}`);
    console.log('');
  }
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
