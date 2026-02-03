# OAuth 2.0 Authorization Server

A production grade, multi tenant OAuth 2.0 Authorization Server built with Hono and TypeScript.

## Features

* RFC 6749 (OAuth 2.0 Framework)
* RFC 6750 (Bearer Tokens)
* RFC 8628 (Device Authorization Grant)
* RFC 9700 (Security Best Current Practice)
* Multi tenant architecture with complete data isolation
* Pluggable user authentication
* Prisma ORM with PostgreSQL

## Supported Grant Types

* Authorization Code with PKCE (required for all clients)
* Client Credentials
* Device Code
* Refresh Token with rotation

## Quick Start

### Prerequisites

* Node.js 20 or later
* PostgreSQL (optional, can use in memory storage for development)

### Installation

```bash
npm install
```

### Development (In Memory Storage)

```bash
npm run dev
```

The server starts with in memory storage. All data is lost on restart.

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
npm run dev
```

### Endpoints

All endpoints are scoped by tenant using the URL path.

| Endpoint | Path |
|----------|------|
| Discovery | `/<tenant>/.well-known/openid-configuration` |
| JWKS | `/<tenant>/.well-known/jwks.json` |
| Authorization | `/<tenant>/authorize` |
| Token | `/<tenant>/token` |
| Revocation | `/<tenant>/revoke` |
| Introspection | `/<tenant>/introspect` |
| Device Authorization | `/<tenant>/device_authorization` |

### Example: Client Credentials Flow

```bash
# Get access token
curl -X POST http://localhost:3000/dev/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read"
```

### Example: Authorization Code Flow

1. Redirect user to authorization endpoint

```
http://localhost:3000/dev/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=http://localhost:3001/callback&
  scope=openid profile&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256&
  state=STATE
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

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3000 | Server port |
| HOST | 0.0.0.0 | Server host |
| DATABASE_URL | | PostgreSQL connection string |
| NODE_ENV | development | Environment mode |

See `.env.example` for all options.

## Project Structure

```
src/
  app.ts              Application factory
  index.ts            Entry point
  config/             Configuration and constants
  types/              TypeScript type definitions
  errors/             OAuth error handling
  crypto/             JWT, PKCE, hashing utilities
  storage/
    interfaces/       Abstract storage contracts
    memory/           In memory implementation
    prisma/           Prisma implementation
  middleware/         Hono middleware
  services/           Token and scope services
  grants/             Grant type handlers
  routes/             HTTP route definitions
```

## Documentation

See the `docs/` directory for detailed documentation:

* [Architecture](docs/architecture.md)
* [Grant Types](docs/grant-types.md)
* [Multi Tenancy](docs/multi-tenancy.md)
* [Security](docs/security.md)
* [Storage](docs/storage.md)
* [Integration](docs/integration.md)

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript |
| `npm run start` | Run compiled server |
| `npm run test` | Run tests in watch mode |
| `npm run test:run` | Run tests once |
| `npm run db:push` | Push Prisma schema to database |
| `npm run db:seed` | Seed database with sample data |
| `npm run db:studio` | Open Prisma Studio |
| `npm run typecheck` | Type check without emitting |

## License

MIT
