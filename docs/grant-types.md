# Grant Types

This document describes the OAuth 2.0 grant types supported by the server.

## Authorization Code with PKCE

The authorization code grant is used by web applications, mobile apps, and single page applications. PKCE (Proof Key for Code Exchange) is required for all clients per RFC 9700.

### Flow

1. Client generates a random `code_verifier` (43 to 128 characters)
2. Client computes `code_challenge` as `BASE64URL(SHA256(code_verifier))`
3. Client redirects user to authorization endpoint
4. User authenticates and grants consent
5. Server redirects back with authorization code
6. Client exchanges code for tokens, including the `code_verifier`
7. Server validates the verifier against the stored challenge

### Authorization Request

```
GET /:tenant/authorize
  ?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile email
  &state=RANDOM_STATE
  &code_challenge=CODE_CHALLENGE
  &code_challenge_method=S256
  &nonce=RANDOM_NONCE
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| response_type | Yes | Must be `code` |
| client_id | Yes | Client identifier |
| redirect_uri | Yes | Must exactly match a registered URI |
| scope | No | Space separated scopes |
| state | Recommended | Random value for CSRF protection |
| code_challenge | Yes | PKCE code challenge |
| code_challenge_method | Yes | Must be `S256` |
| nonce | No | Random value for ID token binding |

### Authorization Response

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback
  ?code=AUTHORIZATION_CODE
  &state=RANDOM_STATE
  &iss=https://auth.example.com/tenant
```

The `iss` parameter is included per RFC 9700 for mix up attack prevention.

### Token Request

```
POST /:tenant/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://app.example.com/callback
&code_verifier=CODE_VERIFIER
&client_id=CLIENT_ID
&client_secret=CLIENT_SECRET
```

Confidential clients must authenticate. Public clients only provide `client_id`.

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiI..."
}
```

## Client Credentials

The client credentials grant is used for machine to machine communication where no user is involved. Only confidential clients can use this grant.

### Token Request

```
POST /:tenant/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

grant_type=client_credentials
&scope=api:read api:write
```

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

No refresh token is issued because the client can always request a new access token using its credentials.

## Refresh Token

The refresh token grant is used to obtain new access tokens without user interaction.

### Token Request

```
POST /:tenant/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&scope=openid profile
&client_id=CLIENT_ID
&client_secret=CLIENT_SECRET
```

The `scope` parameter is optional. If provided, it must be a subset of the original scopes.

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "bmV3IHJlZnJlc2ggdG9rZW4...",
  "scope": "openid profile"
}
```

### Refresh Token Rotation

Each refresh token can only be used once. A new refresh token is issued with each refresh request. This limits the window of opportunity if a token is compromised.

The server tracks token families to detect replay attacks. If a revoked refresh token is used, all tokens in that family are revoked immediately.

## Device Code

The device code grant (RFC 8628) is used by devices with limited input capabilities such as smart TVs, game consoles, or CLI tools.

### Device Authorization Request

```
POST /:tenant/device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID
&scope=openid profile
```

### Device Authorization Response

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg...",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/dev/device",
  "verification_uri_complete": "https://auth.example.com/dev/device?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}
```

### User Verification

Display the `user_code` and `verification_uri` to the user. They navigate to the URI on another device and enter the code.

### Token Polling

The device polls the token endpoint at the specified interval:

```
POST /:tenant/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=GmRhmhcxhwAzkoEqiMEg...
&client_id=CLIENT_ID
```

Possible responses:

| Response | Description |
|----------|-------------|
| `authorization_pending` | User has not completed authorization |
| `slow_down` | Polling too frequently, increase interval |
| `expired_token` | Device code has expired |
| `access_denied` | User denied the request |
| Token response | User authorized, tokens returned |

## Scopes

### Standard Scopes

| Scope | Description |
|-------|-------------|
| openid | Request ID token |
| profile | Access to name, picture |
| email | Access to email, email_verified |
| offline_access | Request refresh token |

### Custom Scopes

Define custom scopes per tenant in the tenant configuration. Clients must be explicitly granted access to scopes they can request.
