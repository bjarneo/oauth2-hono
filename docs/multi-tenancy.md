# Multi Tenancy

This document describes the multi tenant architecture of the OAuth server.

## Overview

The server supports multiple tenants (organizations) in a single deployment. Each tenant has:

* Isolated data (clients, tokens, codes)
* Independent configuration (token TTLs, allowed grants, scopes)
* Separate signing keys for JWTs
* Unique issuer identifier

## Tenant Resolution

Tenants are identified by a slug in the URL path:

```
https://auth.example.com/{tenant}/token
https://auth.example.com/{tenant}/authorize
https://auth.example.com/{tenant}/.well-known/openid-configuration
```

The `tenantResolver` middleware extracts the tenant slug and loads the tenant configuration. All subsequent operations are scoped to that tenant.

## Tenant Configuration

Each tenant has configurable settings:

| Setting | Description | Default |
|---------|-------------|---------|
| name | Display name | Required |
| slug | URL identifier | Required |
| issuer | JWT issuer claim | `{baseUrl}/{slug}` |
| allowedGrants | Enabled grant types | All grants |
| allowedScopes | Available scopes | OpenID scopes |
| accessTokenTtl | Access token lifetime (seconds) | 3600 |
| refreshTokenTtl | Refresh token lifetime (seconds) | 2592000 |
| authorizationCodeTtl | Code lifetime (seconds) | 600 |
| deviceCodeTtl | Device code lifetime (seconds) | 1800 |
| deviceCodeInterval | Polling interval (seconds) | 5 |

## Creating Tenants

### Using Seed Script

The seed script (`prisma/seed.ts`) creates tenants during initial setup:

```typescript
await prisma.tenant.create({
  data: {
    name: 'My Organization',
    slug: 'myorg',
    issuer: 'https://auth.example.com/myorg',
    allowedGrants: ['authorization_code', 'refresh_token'],
    allowedScopes: ['openid', 'profile', 'email'],
  },
});
```

### Programmatically

Use the storage interface to create tenants at runtime:

```typescript
const tenant = await storage.tenants.create({
  name: 'My Organization',
  slug: 'myorg',
  issuer: 'https://auth.example.com/myorg',
});
```

## Signing Keys

Each tenant has independent signing keys for JWTs. Keys are automatically generated when a tenant is first accessed.

Multiple keys per tenant are supported for key rotation:

1. Create a new key with `isPrimary: false`
2. Wait for existing tokens to expire
3. Set the new key as primary
4. Delete the old key

The JWKS endpoint (`/.well-known/jwks.json`) returns all non expired keys for the tenant, allowing token validation during rotation.

## Client Isolation

Clients belong to a single tenant. The `clientId` is unique within a tenant but not globally:

```
tenant: acme
client: web-app
full identifier: acme:web-app

tenant: contoso
client: web-app
full identifier: contoso:web-app
```

This allows different organizations to use the same client names without conflicts.

## Token Isolation

All tokens (authorization codes, refresh tokens, device codes) are scoped by tenant. A token from one tenant cannot be used with another tenant.

The `tenant_id` claim is included in JWT access tokens for verification by resource servers.

## Discovery

Each tenant has its own discovery endpoint:

```
GET /{tenant}/.well-known/openid-configuration
```

Returns tenant specific configuration including endpoints and supported features.

## Use Cases

### SaaS Platform

A SaaS platform can create a tenant for each customer organization:

```
customer-a.auth.example.com -> tenant: customer-a
customer-b.auth.example.com -> tenant: customer-b
```

With a reverse proxy, you can use custom domains per tenant.

### Development and Production

Separate tenants for different environments:

```
auth.example.com/dev -> Development
auth.example.com/staging -> Staging
auth.example.com/prod -> Production
```

### Multiple Applications

Different tenants for different applications with shared infrastructure:

```
auth.example.com/app1 -> Application 1
auth.example.com/app2 -> Application 2
```

## Database Schema

Tenant data is stored in the `tenants` table. All other tables have a `tenantId` foreign key with cascade delete enabled.

```
tenants
  └── signing_keys
  └── clients
  └── authorization_codes
  └── refresh_tokens
  └── device_codes
  └── revoked_tokens
```

Deleting a tenant removes all associated data automatically.
