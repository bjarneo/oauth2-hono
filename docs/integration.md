# Integration

This document describes how to integrate the OAuth server with your application.

## User Authentication

The OAuth server does not manage users. You provide a user authenticator that integrates with your existing user system.

### IUserAuthenticator Interface

```typescript
interface IUserAuthenticator {
  authenticate(ctx: Context): Promise<AuthenticationResult>;
  getConsent(tenantId: string, userId: string, clientId: string): Promise<string[] | null>;
  saveConsent(tenantId: string, userId: string, clientId: string, scopes: string[]): Promise<void>;
  revokeConsent(tenantId: string, userId: string, clientId: string): Promise<void>;
  getUserById?(tenantId: string, userId: string): Promise<User | null>;
}

type AuthenticationResult =
  | { authenticated: true; user: User }
  | { authenticated: false; redirectTo: string };
```

### Implementation Example

```typescript
import type { IUserAuthenticator, AuthenticationResult } from 'oauth2-hono';
import type { Context } from 'hono';
import { getCookie } from 'hono/cookie';

class MyUserAuthenticator implements IUserAuthenticator {
  constructor(
    private sessionStore: SessionStore,
    private consentStore: ConsentStore
  ) {}

  async authenticate(ctx: Context): Promise<AuthenticationResult> {
    // Check for session cookie
    const sessionId = getCookie(ctx, 'session_id');

    if (!sessionId) {
      // No session, redirect to login
      const returnUrl = encodeURIComponent(ctx.req.url);
      return {
        authenticated: false,
        redirectTo: `/login?return=${returnUrl}`,
      };
    }

    // Validate session
    const session = await this.sessionStore.get(sessionId);
    if (!session || session.expiresAt < new Date()) {
      return {
        authenticated: false,
        redirectTo: '/login',
      };
    }

    // Return user
    return {
      authenticated: true,
      user: {
        id: session.userId,
        username: session.username,
        email: session.email,
        name: session.displayName,
      },
    };
  }

  async getConsent(tenantId: string, userId: string, clientId: string): Promise<string[] | null> {
    return this.consentStore.get(tenantId, userId, clientId);
  }

  async saveConsent(tenantId: string, userId: string, clientId: string, scopes: string[]): Promise<void> {
    await this.consentStore.save({ tenantId, userId, clientId, scopes });
  }

  async revokeConsent(tenantId: string, userId: string, clientId: string): Promise<void> {
    await this.consentStore.delete(tenantId, userId, clientId);
  }

  async getUserById(tenantId: string, userId: string) {
    return this.userStore.findById(userId);
  }
}
```

### Login Flow

1. User visits authorization endpoint
2. `authenticate()` is called
3. If not authenticated, return redirect URL to your login page
4. Login page authenticates user and creates session
5. Login page redirects back to original authorization URL
6. `authenticate()` now returns the user
7. OAuth flow continues

### Consent Management

For third party applications, the server checks and stores user consent:

1. `getConsent()` checks for existing consent
2. If no consent or insufficient scopes, server returns consent requirements
3. User grants or denies consent
4. `saveConsent()` stores the decision
5. OAuth flow continues

First party applications can skip consent by setting `firstParty: true` on the client.

## Resource Server Integration

Resource servers validate access tokens to protect APIs.

### Token Validation

Validate JWTs using the JWKS endpoint:

```typescript
import * as jose from 'jose';

const jwks = jose.createRemoteJWKSet(
  new URL('https://auth.example.com/tenant/.well-known/jwks.json')
);

async function validateToken(token: string) {
  const { payload } = await jose.jwtVerify(token, jwks, {
    issuer: 'https://auth.example.com/tenant',
    audience: 'expected-client-id', // optional
  });

  return payload;
}
```

### Express Middleware Example

```typescript
import { expressjwt } from 'express-jwt';
import jwksRsa from 'jwks-rsa';

app.use(
  expressjwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksUri: 'https://auth.example.com/tenant/.well-known/jwks.json',
    }),
    issuer: 'https://auth.example.com/tenant',
    algorithms: ['RS256'],
  })
);
```

### Scope Validation

Check scopes in the token payload:

```typescript
function requireScopes(...requiredScopes: string[]) {
  return (req, res, next) => {
    const tokenScopes = req.auth.scope?.split(' ') || [];
    const hasScopes = requiredScopes.every(s => tokenScopes.includes(s));

    if (!hasScopes) {
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required scopes: ${requiredScopes.join(' ')}`,
      });
    }

    next();
  };
}

app.get('/api/data', requireScopes('api:read'), (req, res) => {
  // User has api:read scope
});
```

## Client Application Integration

### Web Application (Confidential Client)

```typescript
// Initiate authorization
const state = crypto.randomUUID();
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store state and verifier in session
session.state = state;
session.codeVerifier = codeVerifier;

const authUrl = new URL('https://auth.example.com/tenant/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', 'https://app.example.com/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

res.redirect(authUrl.toString());
```

```typescript
// Handle callback
const { code, state, iss } = req.query;

// Verify state
if (state !== session.state) {
  throw new Error('Invalid state');
}

// Verify issuer
if (iss !== 'https://auth.example.com/tenant') {
  throw new Error('Invalid issuer');
}

// Exchange code for tokens
const response = await fetch('https://auth.example.com/tenant/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://app.example.com/callback',
    code_verifier: session.codeVerifier,
  }),
});

const tokens = await response.json();
// { access_token, refresh_token, id_token, ... }
```

### Single Page Application (Public Client)

Use a library like oidc-client-ts:

```typescript
import { UserManager } from 'oidc-client-ts';

const userManager = new UserManager({
  authority: 'https://auth.example.com/tenant',
  client_id: 'spa-client-id',
  redirect_uri: 'https://spa.example.com/callback',
  response_type: 'code',
  scope: 'openid profile',
});

// Initiate login
await userManager.signinRedirect();

// Handle callback
const user = await userManager.signinRedirectCallback();

// Use access token
const response = await fetch('https://api.example.com/data', {
  headers: {
    Authorization: `Bearer ${user.access_token}`,
  },
});
```

### Backend Service (Client Credentials)

```typescript
async function getAccessToken() {
  const response = await fetch('https://auth.example.com/tenant/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api:read api:write',
    }),
  });

  const { access_token, expires_in } = await response.json();
  return access_token;
}
```

## Token Refresh

```typescript
async function refreshTokens(refreshToken: string) {
  const response = await fetch('https://auth.example.com/tenant/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET, // if confidential client
    }),
  });

  if (!response.ok) {
    // Refresh failed, user needs to re-authenticate
    throw new Error('Token refresh failed');
  }

  return response.json();
}
```

## PKCE Implementation

Generate code verifier and challenge:

```typescript
function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
```
