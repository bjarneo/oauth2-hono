# Admin Panel

This document describes the admin panel and admin API for managing the OAuth server.

## Overview

The admin panel provides a web interface for managing tenants, OAuth clients, signing keys, tokens, and identity providers. It communicates with the server through the admin API.

## Getting Started

### Starting the Admin Panel

```bash
npm run dev --workspace=@oauth2-hono/admin
```

The admin panel runs on port 5173 by default and connects to the OAuth server at port 3000.

### Configuration

The admin panel uses environment variables for configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| VITE_API_URL | http://localhost:3000 | OAuth server URL |
| VITE_ADMIN_API_KEY | | Admin API key |

Create a `.env` file in `packages/admin/`:

```bash
VITE_API_URL=http://localhost:3000
VITE_ADMIN_API_KEY=your-admin-api-key
```

## Admin API Authentication

The admin API uses API key authentication. Include the key in the `X-Admin-Key` header:

```bash
curl http://localhost:3000/_admin/tenants \
  -H "X-Admin-Key: your-admin-api-key"
```

Configure the API key on the server using the `ADMIN_API_KEY` environment variable or the `admin.auth.apiKey` option:

```typescript
const server = createOAuth2Server({
  storage,
  admin: {
    enabled: true,
    auth: {
      apiKey: 'your-admin-api-key',
      headerName: 'X-Admin-Key', // optional, this is the default
    },
  },
});
```

In development mode without an API key configured, all admin requests are allowed.

## Pages

### Dashboard

The dashboard provides an overview of the system:

* Total number of tenants
* Total number of OAuth clients
* Active refresh tokens count
* Active identity providers count

Quick actions allow creating new tenants and managing keys.

### Tenant Management

#### Tenant List

View all tenants with their name, slug, issuer URL, and allowed grants.

Actions:
* Create new tenant
* View tenant details
* Edit tenant configuration
* Delete tenant (with confirmation)

#### Tenant Details

View complete tenant configuration including:

* Basic information (name, slug, issuer)
* Allowed grants and scopes
* Token TTL settings
* PKCE requirements

Links to manage the tenant's clients, signing keys, tokens, and identity providers.

#### Create/Edit Tenant

Configure tenant settings:

* Name and slug (slug is URL-safe identifier)
* Issuer URL (defaults to server URL with tenant slug)
* Allowed grant types
* Allowed OAuth scopes
* Access token and refresh token TTL
* Authorization code TTL
* Device code settings

### Client Management

#### Client List

View all OAuth clients for a tenant with:

* Client name and description
* Client ID (with copy button)
* Client type (confidential/public)
* Authentication method
* Allowed grants

Actions:
* Create new client
* View client details
* Delete client

#### Client Details

View complete client configuration:

* Basic information
* Client ID and type
* Redirect URIs
* Allowed grants and scopes
* Token settings
* Consent settings

Actions:
* Regenerate client secret (shows new secret in dialog)
* Delete client

#### Create Client

Configure OAuth client:

* Name and description
* Client type (confidential or public)
* Authentication method (client_secret_basic, client_secret_post, private_key_jwt, none)
* Redirect URIs
* Allowed grant types
* Allowed scopes
* Default scopes
* Access and refresh token TTL overrides
* Require user consent
* First party flag (skip consent for trusted apps)

After creation, the client ID and secret are displayed. The secret is only shown once.

### Signing Key Management

View and manage JWT signing keys for a tenant.

#### Key List

Shows all signing keys with:

* Key ID (kid)
* Algorithm (RS256, RS384, RS512, ES256, ES384, ES512)
* Status (Primary or Backup)
* Creation date
* Expiration date (if set)

Actions:
* Create new key
* Rotate keys (creates new primary, demotes current)
* Set a backup key as primary
* Delete key (cannot delete primary if other keys exist)

#### Key Rotation

The rotate action:

1. Creates a new signing key
2. Sets the new key as primary
3. Demotes the previous primary to backup

Old keys are kept for token verification until they expire or are manually deleted.

### Token Management

View and revoke refresh tokens for a tenant.

#### Token List

Shows active refresh tokens with:

* User ID
* Client ID
* Granted scopes
* Issue date
* Expiration date
* Status (Active, Expired, Revoked)

Filters:
* Filter by user ID

Actions:
* Revoke individual token
* Revoke all tokens for a user

### Identity Provider Management

Configure external identity providers for federated authentication.

#### Provider List

Shows all configured identity providers with:

* Provider name
* Provider type (OIDC, OAuth 2.0)
* Enabled status

Actions:
* Create new provider
* Toggle enabled/disabled
* View/edit provider details
* Delete provider

#### Create/Edit Provider

Configure identity provider:

* Name and slug
* Provider template (Google, GitHub, Microsoft, etc.)
* Provider type
* Client ID and secret
* OAuth endpoints (auto-filled for templates)
* Scopes to request
* Attribute mapping
* Display settings (icon URL, button text)

## API Reference

See the main README for complete admin API endpoint documentation.

### Response Format

All admin API responses follow this format:

Success:
```json
{
  "data": { ... }
}
```

List endpoints include pagination:
```json
{
  "data": [ ... ],
  "pagination": {
    "total": 100,
    "limit": 20,
    "offset": 0
  }
}
```

Errors:
```json
{
  "error": "error_code",
  "error_description": "Human readable message"
}
```

### Pagination

List endpoints support pagination with query parameters:

* `limit` (default: 20, max: 100)
* `offset` (default: 0)

Example:
```bash
curl "http://localhost:3000/_admin/tenants?limit=10&offset=20" \
  -H "X-Admin-Key: your-api-key"
```

## Tech Stack

The admin panel is built with:

* React 18 with TypeScript
* React Router for navigation
* TanStack Query for server state management
* Tailwind CSS for styling
* shadcn/ui components (built on Radix UI)
* Vite for development and builds

## Development

### Project Structure

```
packages/admin/src/
  App.tsx               Application root with routing
  main.tsx              Entry point
  index.css             Global styles and Tailwind imports
  api/
    client.ts           API client with error handling
  components/
    Layout.tsx          Main layout with sidebar
    ui/                 shadcn/ui component library
  pages/
    Dashboard.tsx
    tenants/
      TenantList.tsx
      TenantCreate.tsx
      TenantDetail.tsx
      TenantEdit.tsx
    clients/
      ClientList.tsx
      ClientCreate.tsx
      ClientDetail.tsx
    signing-keys/
      SigningKeys.tsx
    tokens/
      TokenList.tsx
    identity-providers/
      IdentityProviderList.tsx
      IdentityProviderCreate.tsx
      IdentityProviderDetail.tsx
```

### Adding Components

The admin panel uses shadcn/ui. To add new components:

```bash
cd packages/admin
npx shadcn@latest add button
```

### Building for Production

```bash
npm run build --workspace=@oauth2-hono/admin
```

The build output is in `packages/admin/dist/`.
