# Architecture

This document describes the overall architecture of the OAuth 2.0 Authorization Server.

## Overview

The server is built on Hono, a lightweight web framework for TypeScript. It follows a layered architecture with clear separation of concerns.

```
┌─────────────────────────────────────────────────────┐
│                    HTTP Layer                        │
│              (Hono Routes + Middleware)             │
├─────────────────────────────────────────────────────┤
│                   Service Layer                      │
│           (Token Service, Scope Service)            │
├─────────────────────────────────────────────────────┤
│                   Grant Handlers                     │
│    (Authorization Code, Client Credentials, etc)    │
├─────────────────────────────────────────────────────┤
│                  Storage Layer                       │
│         (Interfaces + Implementations)              │
├─────────────────────────────────────────────────────┤
│                    Database                          │
│          (PostgreSQL or In Memory)                  │
└─────────────────────────────────────────────────────┘
```

## Components

### Application Factory (app.ts)

The `createOAuth2Server` function creates a configured Hono application. It accepts options for storage, user authentication, rate limiting, and other settings.

```typescript
const app = createOAuth2Server({
  storage,
  userAuthenticator,
  baseUrl: 'https://auth.example.com',
  rateLimit: { windowMs: 60000, maxRequests: 100 },
});
```

### Middleware

Middleware functions handle cross cutting concerns:

| Middleware | Purpose |
|------------|---------|
| tenantResolver | Resolves tenant from URL path and loads signing keys |
| clientAuthenticator | Validates client credentials (Basic, POST, JWT) |
| bearerAuth | Validates access tokens for protected endpoints |
| rateLimiter | Prevents abuse with configurable limits |
| errorHandler | Transforms errors into RFC compliant responses |

### Grant Handlers

Each grant type has a dedicated handler in `src/grants/`:

| Grant | Handler |
|-------|---------|
| Authorization Code | `grants/authorization-code/handler.ts` |
| Client Credentials | `grants/client-credentials/handler.ts` |
| Refresh Token | `grants/refresh-token/handler.ts` |
| Device Code | `grants/device-code/handler.ts` |

The authorization endpoint is handled separately in `grants/authorization-code/authorize.ts` because it has different concerns (user authentication, consent).

### Services

Services encapsulate business logic:

| Service | Purpose |
|---------|---------|
| TokenService | Generates access tokens, refresh tokens, ID tokens |
| ScopeService | Validates and manipulates OAuth scopes |

### Storage Layer

The storage layer uses interfaces to abstract data access. This allows switching between implementations without changing business logic.

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

Two implementations are provided:

1. **Memory Storage** for development and testing
2. **Prisma Storage** for production with PostgreSQL

## Request Flow

A typical token request flows through these steps:

1. Request arrives at `POST /:tenant/token`
2. `tenantResolver` middleware loads tenant configuration
3. `clientAuthenticator` middleware validates client credentials
4. Route handler parses `grant_type` and delegates to appropriate grant handler
5. Grant handler validates request and calls services
6. `TokenService` generates tokens using tenant signing key
7. Response returned with cache control headers

## Error Handling

All errors are transformed into RFC compliant OAuth error responses:

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired"
}
```

The `OAuthError` class provides factory methods for standard errors:

```typescript
throw OAuthError.invalidGrant('Authorization code has expired');
throw OAuthError.invalidClient('Unknown client');
throw OAuthError.invalidScope('Scope not allowed');
```

## Configuration

Configuration is loaded from environment variables at startup. The `Config` object is available throughout the application via `getConfig()`.

Settings can be overridden at multiple levels:

1. Environment variables (global defaults)
2. Tenant configuration (per tenant)
3. Client configuration (per client)

For example, token TTLs can be configured globally, overridden for a tenant, and further customized for specific clients.
