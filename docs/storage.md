# Storage

This document describes the storage layer and how to implement custom storage adapters.

## Overview

The storage layer uses interfaces to abstract data access. This allows:

* Switching between databases without changing business logic
* Using in memory storage for testing
* Implementing custom storage backends

## Storage Interface

The main storage interface combines all sub interfaces:

```typescript
interface IStorage {
  tenants: ITenantStorage;
  signingKeys: ISigningKeyStorage;
  clients: IClientStorage;
  refreshTokens: IRefreshTokenStorage;
  revokedTokens: IRevokedTokenStorage;
  authorizationCodes: IAuthorizationCodeStorage;
  deviceCodes: IDeviceCodeStorage;
}
```

## Available Implementations

### Memory Storage

In memory implementation for development and testing:

```typescript
import { createMemoryStorage } from 'oauth2-hono';

const storage = createMemoryStorage();
```

Data is lost when the process stops. Useful for:

* Development without database setup
* Unit testing
* Quick prototyping

### Prisma Storage

PostgreSQL implementation using Prisma ORM:

```typescript
import { createPrismaStorage } from 'oauth2-hono';

const storage = createPrismaStorage();
```

Requires:

* PostgreSQL database
* DATABASE_URL environment variable
* Prisma schema pushed with `npm run db:push`

## Sub Interfaces

### ITenantStorage

```typescript
interface ITenantStorage {
  create(input: CreateTenantInput): Promise<Tenant>;
  findById(id: string): Promise<Tenant | null>;
  findBySlug(slug: string): Promise<Tenant | null>;
  update(id: string, input: UpdateTenantInput): Promise<Tenant>;
  delete(id: string): Promise<void>;
  list(options?: { limit?: number; offset?: number }): Promise<Tenant[]>;
}
```

### ISigningKeyStorage

```typescript
interface ISigningKeyStorage {
  create(input: CreateSigningKeyInput): Promise<SigningKey>;
  findById(id: string): Promise<SigningKey | null>;
  findByKid(tenantId: string, kid: string): Promise<SigningKey | null>;
  getPrimary(tenantId: string): Promise<SigningKey | null>;
  listByTenant(tenantId: string): Promise<SigningKey[]>;
  setPrimary(id: string): Promise<SigningKey>;
  delete(id: string): Promise<void>;
  deleteExpired(tenantId: string): Promise<number>;
}
```

### IClientStorage

```typescript
interface IClientStorage {
  create(input: CreateClientInput): Promise<{ client: OAuthClient; clientSecret?: string }>;
  findById(id: string): Promise<OAuthClient | null>;
  findByClientId(tenantId: string, clientId: string): Promise<OAuthClient | null>;
  update(id: string, input: UpdateClientInput): Promise<OAuthClient>;
  regenerateSecret(id: string): Promise<string>;
  delete(id: string): Promise<void>;
  listByTenant(tenantId: string, options?: { limit?: number; offset?: number }): Promise<OAuthClient[]>;
  verifyCredentials(tenantId: string, clientId: string, clientSecret: string): Promise<OAuthClient | null>;
}
```

### IAuthorizationCodeStorage

```typescript
interface IAuthorizationCodeStorage {
  create(input: CreateAuthorizationCodeInput): Promise<{ code: AuthorizationCode; value: string }>;
  findByHash(tenantId: string, codeHash: string): Promise<AuthorizationCode | null>;
  findByValue(tenantId: string, codeValue: string): Promise<AuthorizationCode | null>;
  consume(tenantId: string, codeValue: string): Promise<AuthorizationCode | null>;
  deleteExpired(tenantId: string): Promise<number>;
}
```

The `consume` method must be atomic to prevent authorization code reuse.

### IRefreshTokenStorage

```typescript
interface IRefreshTokenStorage {
  create(input: CreateRefreshTokenInput): Promise<{ token: RefreshToken; value: string }>;
  findByHash(tenantId: string, tokenHash: string): Promise<RefreshToken | null>;
  findByValue(tenantId: string, tokenValue: string): Promise<RefreshToken | null>;
  revoke(id: string): Promise<void>;
  revokeFamily(tenantId: string, familyId: string): Promise<number>;
  revokeByUserAndClient(tenantId: string, userId: string, clientId: string): Promise<number>;
  revokeByUser(tenantId: string, userId: string): Promise<number>;
  isRevoked(id: string): Promise<boolean>;
  deleteExpired(tenantId: string): Promise<number>;
}
```

### IRevokedTokenStorage

Used for tracking revoked JWT access tokens:

```typescript
interface IRevokedTokenStorage {
  revoke(tenantId: string, tokenId: string, tokenType: string, expiresAt: Date): Promise<RevokedToken>;
  isRevoked(tenantId: string, tokenId: string): Promise<boolean>;
  deleteExpired(tenantId: string): Promise<number>;
}
```

### IDeviceCodeStorage

```typescript
interface IDeviceCodeStorage {
  create(input: CreateDeviceCodeInput): Promise<{ deviceCode: DeviceCode; deviceCodeValue: string; userCode: string }>;
  findByHash(tenantId: string, deviceCodeHash: string): Promise<DeviceCode | null>;
  findByValue(tenantId: string, deviceCodeValue: string): Promise<DeviceCode | null>;
  findByUserCode(tenantId: string, userCode: string): Promise<DeviceCode | null>;
  updateLastPolled(id: string): Promise<boolean>;
  authorize(id: string, userId: string): Promise<DeviceCode>;
  deny(id: string): Promise<DeviceCode>;
  consume(id: string): Promise<void>;
  deleteExpired(tenantId: string): Promise<number>;
}
```

## Implementing Custom Storage

To implement a custom storage backend:

1. Create classes implementing each interface
2. Create a factory function that returns an `IStorage` object
3. Pass the storage to `createOAuth2Server`

Example for Redis:

```typescript
import { IStorage, ITenantStorage, IClientStorage } from 'oauth2-hono';

class RedisTenantStorage implements ITenantStorage {
  constructor(private redis: RedisClient) {}

  async findBySlug(slug: string): Promise<Tenant | null> {
    const data = await this.redis.get(`tenant:slug:${slug}`);
    return data ? JSON.parse(data) : null;
  }

  // ... implement other methods
}

export function createRedisStorage(redis: RedisClient): IStorage {
  return {
    tenants: new RedisTenantStorage(redis),
    signingKeys: new RedisSigningKeyStorage(redis),
    clients: new RedisClientStorage(redis),
    refreshTokens: new RedisRefreshTokenStorage(redis),
    revokedTokens: new RedisRevokedTokenStorage(redis),
    authorizationCodes: new RedisAuthorizationCodeStorage(redis),
    deviceCodes: new RedisDeviceCodeStorage(redis),
  };
}
```

## Database Schema (Prisma)

The Prisma schema is in `prisma/schema.prisma`. Key tables:

| Table | Purpose |
|-------|---------|
| tenants | Tenant configuration |
| signing_keys | JWT signing keys |
| clients | OAuth clients |
| authorization_codes | Authorization codes |
| refresh_tokens | Refresh tokens |
| device_codes | Device authorization codes |
| revoked_tokens | Revoked JWT tracking |

All tables have `tenantId` foreign keys with cascade delete.

## Cleanup

Expired tokens and codes should be periodically cleaned up:

```typescript
await storage.authorizationCodes.deleteExpired(tenantId);
await storage.refreshTokens.deleteExpired(tenantId);
await storage.deviceCodes.deleteExpired(tenantId);
await storage.revokedTokens.deleteExpired(tenantId);
```

Consider running cleanup as a scheduled job in production.
