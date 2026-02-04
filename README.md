# OAuth 2.0 Authorization Server

A production grade, multi tenant OAuth 2.0 and OpenID Connect authorization server built with Hono and TypeScript. Includes a React admin panel for managing tenants, clients, and identity providers.

## Features

### Standards Compliance

* RFC 6749 (OAuth 2.0 Framework)
* RFC 6750 (Bearer Tokens)
* RFC 7591 (Dynamic Client Registration)
* RFC 8628 (Device Authorization Grant)
* RFC 9700 (Security Best Current Practice)
* OpenID Connect Core 1.0
* OpenID Connect Discovery 1.0
* OpenID Connect RP Initiated Logout 1.0
* OpenID Connect Back Channel Logout 1.0

### Core Capabilities

* Multi tenant architecture with complete data isolation
* Pluggable storage backends (in memory or PostgreSQL via Prisma)
* Pluggable user authentication
* Identity provider federation (Google, GitHub, Microsoft, Apple, and more)
* Admin API with API key authentication
* React admin panel for configuration management

### Supported Grant Types

* Authorization Code with PKCE (required for all clients)
* Client Credentials
* Device Code
* Refresh Token with rotation

## Project Structure

This is a monorepo managed with npm workspaces containing three packages:

```
oauth2-hono/
├── packages/
│   ├── server/          OAuth 2.0 authorization server
│   ├── admin/           React admin panel
│   └── shared/          Shared TypeScript types
├── prisma/              Database schema
└── docs/                Documentation
```

## Quick Start

### Prerequisites

* Node.js 20 or later
* PostgreSQL (optional, can use in memory storage for development)

### Installation

```bash
npm install
```

### Development (In Memory Storage)

Start the OAuth server with in memory storage:

```bash
npm run dev --workspace=@oauth2-hono/server
```

Start the admin panel:

```bash
npm run dev --workspace=@oauth2-hono/admin
```

The server runs on port 3000 and the admin panel on port 5173.

### Development (PostgreSQL)

1. Start PostgreSQL and create a database

2. Copy environment file and configure DATABASE_URL

```bash
cp .env.example .env
```

3. Push the schema and seed the database

```bash
npm run db:push
npm run db:seed
```

4. Start the server

```bash
npm run dev --workspace=@oauth2-hono/server
```

## OAuth Endpoints

All OAuth endpoints are scoped by tenant using the URL path.

| Endpoint | Path |
|----------|------|
| Discovery | `/<tenant>/.well-known/openid-configuration` |
| JWKS | `/<tenant>/.well-known/jwks.json` |
| Authorization | `/<tenant>/authorize` |
| Token | `/<tenant>/token` |
| UserInfo | `/<tenant>/userinfo` |
| Revocation | `/<tenant>/revoke` |
| Introspection | `/<tenant>/introspect` |
| End Session | `/<tenant>/end_session` |
| Device Authorization | `/<tenant>/device_authorization` |
| Client Registration | `/<tenant>/register` |
| Federation Initiate | `/<tenant>/federate/<idp_slug>` |
| Federation Callback | `/<tenant>/federate/<idp_slug>/callback` |

## Admin API

The admin API is mounted at `/_admin/` and requires API key authentication.

### Tenants

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/_admin/tenants` | List all tenants |
| POST | `/_admin/tenants` | Create a tenant |
| GET | `/_admin/tenants/:id` | Get tenant details |
| PUT | `/_admin/tenants/:id` | Update a tenant |
| DELETE | `/_admin/tenants/:id` | Delete a tenant |
| GET | `/_admin/tenants/:id/stats` | Get tenant statistics |

### Clients

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/_admin/tenants/:tenantId/clients` | List clients |
| POST | `/_admin/tenants/:tenantId/clients` | Create a client |
| GET | `/_admin/clients/:id` | Get client details |
| PUT | `/_admin/clients/:id` | Update a client |
| DELETE | `/_admin/clients/:id` | Delete a client |
| POST | `/_admin/clients/:id/regenerate-secret` | Regenerate client secret |

### Signing Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/_admin/tenants/:tenantId/signing-keys` | List signing keys |
| POST | `/_admin/tenants/:tenantId/signing-keys` | Create a signing key |
| POST | `/_admin/tenants/:tenantId/signing-keys/rotate` | Rotate keys |
| PUT | `/_admin/signing-keys/:id/set-primary` | Set key as primary |
| DELETE | `/_admin/signing-keys/:id` | Delete a signing key |

### Tokens

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/_admin/tenants/:tenantId/refresh-tokens` | List refresh tokens |
| POST | `/_admin/refresh-tokens/:id/revoke` | Revoke a token |
| POST | `/_admin/tenants/:tenantId/refresh-tokens/revoke-by-user/:userId` | Revoke all tokens for a user |

### Identity Providers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/_admin/tenants/:tenantId/identity-providers` | List identity providers |
| POST | `/_admin/tenants/:tenantId/identity-providers` | Create an identity provider |
| GET | `/_admin/identity-providers/:id` | Get identity provider details |
| PUT | `/_admin/identity-providers/:id` | Update an identity provider |
| DELETE | `/_admin/identity-providers/:id` | Delete an identity provider |

## Identity Provider Federation

The server supports federated authentication with external identity providers. Users can sign in with their existing accounts from supported providers.

### Supported Providers

* Google
* GitHub
* Microsoft
* Apple
* Facebook
* Twitter
* LinkedIn
* Generic OIDC
* Generic OAuth 2.0

### Federation Flow

1. Configure an identity provider in the admin panel or via the admin API
2. Redirect users to `/<tenant>/federate/<idp_slug>` to initiate authentication
3. The server redirects to the external provider
4. After authentication, the provider redirects back to `/<tenant>/federate/<idp_slug>/callback`
5. The server exchanges the code for tokens and retrieves user information
6. A federated identity is created linking the external account to a local user

### Example: Configure Google as an Identity Provider

```bash
curl -X POST http://localhost:3000/_admin/tenants/TENANT_ID/identity-providers \
  -H "X-Admin-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Google",
    "slug": "google",
    "template": "google",
    "clientId": "YOUR_GOOGLE_CLIENT_ID",
    "clientSecret": "YOUR_GOOGLE_CLIENT_SECRET",
    "scopes": ["openid", "profile", "email"]
  }'
```

## Usage Examples

### Client Credentials Flow

```bash
curl -X POST http://localhost:3000/dev/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read"
```

### Authorization Code Flow

1. Redirect user to authorization endpoint

```
http://localhost:3000/dev/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=http://localhost:3001/callback&
  scope=openid profile email&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256&
  state=STATE&
  nonce=NONCE
```

2. Exchange code for tokens

```bash
curl -X POST http://localhost:3000/dev/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3001/callback" \
  -d "code_verifier=CODE_VERIFIER" \
  -d "client_id=CLIENT_ID"
```

### Get User Info

```bash
curl http://localhost:3000/dev/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### Logout

```
http://localhost:3000/dev/end_session?
  id_token_hint=ID_TOKEN&
  post_logout_redirect_uri=http://localhost:3001&
  state=STATE
```

### Dynamic Client Registration

```bash
curl -X POST http://localhost:3000/dev/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["http://localhost:3001/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

## Response Modes

The authorization endpoint supports three response modes:

| Mode | Description |
|------|-------------|
| query | Parameters in URL query string (default) |
| fragment | Parameters in URL fragment |
| form_post | Parameters POSTed via HTML form (most secure) |

```
http://localhost:3000/dev/authorize?
  response_type=code&
  response_mode=form_post&
  ...
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3000 | Server port |
| HOST | 0.0.0.0 | Server host |
| DATABASE_URL | | PostgreSQL connection string |
| NODE_ENV | development | Environment mode |
| ADMIN_API_KEY | | API key for admin endpoints |
| ENCRYPTION_KEY | | Key for encrypting IdP client secrets |

See `.env.example` for all options.

### Server Options

The `createOAuth2Server` function accepts the following options:

```typescript
interface OAuth2ServerOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  baseUrl?: string;
  verificationUri?: string;
  rateLimit?: { windowMs: number; maxRequests: number };
  enableCors?: boolean;
  enableLogging?: boolean;
  allowOpenRegistration?: boolean;
  registrationAccessToken?: string;
  onLogout?: (tenantId: string, userId: string, clientId?: string) => Promise<void>;
  admin?: {
    enabled?: boolean;
    auth?: AdminAuthOptions;
  };
  federation?: {
    enabled?: boolean;
    onFederatedLogin?: (params: FederatedLoginParams) => Promise<FederatedLoginResult>;
  };
}
```

## OIDC Claims

The server supports standard OpenID Connect claims organized by scope:

| Scope | Claims |
|-------|--------|
| openid | sub |
| profile | name, given_name, family_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at |
| email | email, email_verified |
| address | address |
| phone | phone_number, phone_number_verified |

## Package Structure

### Server Package

```
packages/server/src/
  app.ts              Application factory
  index.ts            Entry point
  config/             Configuration and constants
  types/              TypeScript type definitions
  errors/             OAuth error handling
  crypto/             JWT, PKCE, hashing, encryption utilities
  storage/
    interfaces/       Abstract storage contracts
    memory/           In memory implementation
    prisma/           Prisma implementation
  middleware/         Hono middleware
  services/           Token and scope services
  grants/             Grant type handlers
  routes/
    oauth/            OAuth endpoints
    discovery/        OIDC discovery endpoints
    admin/            Admin API endpoints
    federation/       Identity provider federation
```

### Admin Package

```
packages/admin/src/
  App.tsx             Application root with routing
  api/                API client
  components/         Reusable UI components (shadcn/ui)
  pages/              Page components
    Dashboard.tsx
    tenants/          Tenant management
    clients/          Client management
    signing-keys/     Key management
    tokens/           Token management
    identity-providers/  IdP configuration
```

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev --workspace=@oauth2-hono/server` | Start server with hot reload |
| `npm run dev --workspace=@oauth2-hono/admin` | Start admin panel |
| `npm run build` | Build all packages |
| `npm run test:run` | Run tests once |
| `npm run typecheck` | Type check all packages |
| `npm run db:push` | Push Prisma schema to database |
| `npm run db:seed` | Seed database with sample data |
| `npm run db:studio` | Open Prisma Studio |

## Documentation

See the `docs/` directory for detailed documentation:

* [Architecture](docs/architecture.md)
* [Grant Types](docs/grant-types.md)
* [OpenID Connect](docs/oidc.md)
* [Multi Tenancy](docs/multi-tenancy.md)
* [Security](docs/security.md)
* [Storage](docs/storage.md)
* [Integration](docs/integration.md)
* [OAuth Flow](docs/flow.md)
* [Identity Provider Federation](docs/federation.md)
* [Admin Panel](docs/admin.md)

## Tech Stack

### Server

* Hono (web framework)
* TypeScript
* Prisma (database ORM)
* jose (JWT library)

### Admin Panel

* React 18
* React Router
* TanStack Query
* Tailwind CSS
* shadcn/ui (Radix based components)
* Vite

## License

MIT
