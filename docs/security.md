# Security

This document describes the security measures implemented in the OAuth server.

## RFC 9700 Compliance

The server implements OAuth 2.0 Security Best Current Practice (RFC 9700):

### PKCE Required

PKCE is required for all clients, including confidential clients. This prevents authorization code interception attacks.

Only the S256 challenge method is supported. The plain method is not implemented because it provides no security benefit.

### Exact Redirect URI Matching

Redirect URIs must exactly match a registered URI. Pattern matching and wildcards are not supported.

```
Registered: https://app.example.com/callback
Request:    https://app.example.com/callback     ✓ Valid
Request:    https://app.example.com/callback/    ✗ Invalid
Request:    https://app.example.com/callback?x=1 ✗ Invalid
```

### Issuer in Authorization Response

The `iss` parameter is included in authorization responses to prevent mix up attacks:

```
https://app.example.com/callback?code=...&iss=https://auth.example.com/tenant
```

### Short Lived Authorization Codes

Authorization codes expire after 10 minutes by default and can only be used once.

### Refresh Token Rotation

Refresh tokens are rotated on each use. The previous token is immediately invalidated.

## Token Security

### Access Tokens

Access tokens are JWTs signed with RS256 (RSA with SHA256). They are self contained and not stored in the database.

Token claims include:

| Claim | Description |
|-------|-------------|
| iss | Issuer (tenant specific) |
| sub | Subject (user or client ID) |
| aud | Audience (client ID) |
| exp | Expiration time |
| iat | Issued at |
| jti | Unique token ID |
| client_id | OAuth client |
| scope | Granted scopes |
| tenant_id | Tenant identifier |

### Refresh Tokens

Refresh tokens are opaque random strings. The server stores a SHA256 hash, not the token itself.

Features:

* Single use with rotation
* Family tracking for replay detection
* Configurable expiration

### Authorization Codes

Authorization codes are opaque random strings. The server stores a SHA256 hash.

Features:

* Single use (atomic consumption)
* Short expiration (10 minutes default)
* PKCE binding

## Client Authentication

### client_secret_basic

Credentials sent in the Authorization header:

```
Authorization: Basic BASE64(client_id:client_secret)
```

### client_secret_post

Credentials sent in the request body:

```
client_id=...&client_secret=...
```

### private_key_jwt

Client authenticates using a signed JWT assertion. Requires client to have registered a JWKS.

### none

For public clients (SPAs, mobile apps). No credentials required but PKCE is mandatory.

## Secret Storage

### Client Secrets

Client secrets are hashed using scrypt with the following parameters:

* N = 16384 (CPU/memory cost)
* r = 8 (block size)
* p = 1 (parallelization)
* Salt = 16 random bytes
* Output = 64 bytes

Stored format: `$scrypt$N$r$p$salt$hash`

### Tokens and Codes

Tokens and codes are hashed using SHA256. Since they are high entropy random values, key stretching is not necessary.

## Rate Limiting

Rate limiting protects against brute force attacks:

| Endpoint | Default Limit |
|----------|---------------|
| Token | 30 requests per minute per IP |
| Authorization | 60 requests per minute per IP |
| Device polling | Enforced interval per device code |

Responses include rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
```

## Security Headers

All responses include security headers:

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

Authorization pages include Content Security Policy:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'
```

## Token Responses

Token responses include cache control headers to prevent caching:

```
Cache-Control: no-store
Pragma: no-cache
```

## Timing Attacks

Constant time comparison is used when verifying:

* Client secrets
* Token hashes
* Code challenges

This prevents timing attacks that could leak information about valid credentials.

## Replay Detection

### Authorization Codes

Each code can only be used once. The consumption is atomic to prevent race conditions.

### Refresh Tokens

Tokens are tracked by family. If a previously rotated token is used:

1. The token is already revoked
2. All tokens in the family are revoked
3. User must re authenticate

This detects when an attacker obtains a refresh token that has already been rotated.

## Recommendations

### Production Deployment

* Use HTTPS for all endpoints
* Enable HSTS (Strict Transport Security)
* Configure proper CORS settings
* Use a reverse proxy for TLS termination
* Store secrets in a secret manager
* Monitor for unusual activity

### Client Configuration

* Use confidential clients when possible
* Register specific redirect URIs
* Request minimal scopes
* Implement PKCE correctly
* Handle token expiration gracefully

### User Authentication

* Implement proper session management
* Use secure authentication methods
* Require strong passwords or MFA
* Audit authentication events
