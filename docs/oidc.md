# OpenID Connect

This document describes the OpenID Connect features implemented by the server.

## Specifications Implemented

* OpenID Connect Core 1.0
* OpenID Connect Discovery 1.0
* OpenID Connect RP-Initiated Logout 1.0
* OpenID Connect Back-Channel Logout 1.0
* OpenID Connect Dynamic Client Registration 1.0

## Discovery

The discovery endpoint provides client configuration:

```
GET /:tenant/.well-known/openid-configuration
```

Response includes:

```json
{
  "issuer": "https://auth.example.com/tenant",
  "authorization_endpoint": "https://auth.example.com/tenant/authorize",
  "token_endpoint": "https://auth.example.com/tenant/token",
  "userinfo_endpoint": "https://auth.example.com/tenant/userinfo",
  "jwks_uri": "https://auth.example.com/tenant/.well-known/jwks.json",
  "end_session_endpoint": "https://auth.example.com/tenant/end_session",
  "registration_endpoint": "https://auth.example.com/tenant/register",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "name", "given_name", "family_name", "email", "email_verified", "picture", "locale", "phone_number", "address"],
  "claims_parameter_supported": true,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

## UserInfo Endpoint

Retrieve user claims using an access token:

```
GET /:tenant/userinfo
Authorization: Bearer ACCESS_TOKEN
```

Or via POST:

```
POST /:tenant/userinfo
Authorization: Bearer ACCESS_TOKEN
```

Response claims depend on granted scopes:

| Scope | Claims |
|-------|--------|
| openid | sub |
| profile | name, given_name, family_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, updated_at |
| email | email, email_verified |
| address | address |
| phone | phone_number, phone_number_verified |

Example response:

```json
{
  "sub": "user-123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://example.com/photo.jpg"
}
```

## ID Token Claims

ID tokens include standard OIDC claims:

| Claim | Description |
|-------|-------------|
| iss | Issuer identifier |
| sub | Subject identifier |
| aud | Audience (client ID) |
| exp | Expiration time |
| iat | Issued at time |
| auth_time | Authentication time |
| nonce | Value from authorization request |
| acr | Authentication Context Class Reference |
| amr | Authentication Methods References |
| azp | Authorized party |
| sid | Session ID (for logout) |

Plus claims based on requested scopes (profile, email, address, phone).

## Claims Parameter

Request specific claims in the authorization request:

```json
{
  "id_token": {
    "email": {
      "essential": true
    },
    "email_verified": null,
    "acr": {
      "values": ["urn:example:mfa"]
    }
  },
  "userinfo": {
    "name": null,
    "picture": null
  }
}
```

* Claims with `essential: true` are critical for the application
* Claims with `null` are voluntarily requested
* Claims with `values` array request specific values

## Authentication Context

### ACR Values

Request specific authentication assurance levels:

```
acr_values=urn:example:mfa urn:example:password
```

Values are space-separated and processed in order of preference.

### AMR Claim

The `amr` claim lists authentication methods used:

| Value | Method |
|-------|--------|
| pwd | Password |
| mfa | Multi-factor authentication |
| otp | One-time password |
| sms | SMS verification |
| face | Facial recognition |
| fpt | Fingerprint |
| hwk | Hardware key |

## Logout

### RP-Initiated Logout

Redirect users to end their session:

```
GET /:tenant/end_session
  ?id_token_hint=ID_TOKEN
  &post_logout_redirect_uri=https://app.example.com
  &state=RANDOM_STATE
  &client_id=CLIENT_ID
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| id_token_hint | Recommended | Previously issued ID token |
| post_logout_redirect_uri | No | Redirect after logout (must be registered) |
| state | No | Passed back in redirect |
| client_id | Conditional | Required if id_token_hint not provided |

### Back-Channel Logout

Clients can register to receive logout notifications:

1. Register `backchannel_logout_uri` in client configuration
2. When user logs out, server sends POST request with logout token
3. Client validates token and clears session

Logout token structure:

```json
{
  "iss": "https://auth.example.com/tenant",
  "sub": "user-123",
  "aud": "client-id",
  "iat": 1234567890,
  "jti": "unique-token-id",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  },
  "sid": "session-id"
}
```

The `sid` claim is included if `backchannel_logout_session_required` is true.

### Logout Behavior

On logout, the server:

1. Validates the ID token hint (if provided)
2. Revokes all refresh tokens for the user
3. Revokes stored consent (if applicable)
4. Sends back-channel logout notifications to all registered clients
5. Redirects to post_logout_redirect_uri (if valid) or shows confirmation page

## Dynamic Client Registration

### Register a Client

```
POST /:tenant/register
Content-Type: application/json

{
  "client_name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "contacts": ["admin@example.com"],
  "logo_uri": "https://app.example.com/logo.png",
  "client_uri": "https://app.example.com",
  "policy_uri": "https://app.example.com/privacy",
  "tos_uri": "https://app.example.com/terms",
  "post_logout_redirect_uris": ["https://app.example.com"],
  "backchannel_logout_uri": "https://app.example.com/logout",
  "backchannel_logout_session_required": true
}
```

Response:

```json
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0,
  "client_name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  ...
}
```

### Read Client Configuration

```
GET /:tenant/register/:client_id
```

### Delete Client Registration

```
DELETE /:tenant/register/:client_id
```

## Response Modes

Control how the authorization response is delivered:

### Query Mode (Default)

Parameters in URL query string:

```
https://app.example.com/callback?code=AUTH_CODE&state=STATE&iss=ISSUER
```

### Fragment Mode

Parameters in URL fragment:

```
https://app.example.com/callback#code=AUTH_CODE&state=STATE&iss=ISSUER
```

### Form POST Mode

Server returns HTML page that auto-submits a form:

```html
<form method="POST" action="https://app.example.com/callback">
  <input type="hidden" name="code" value="AUTH_CODE">
  <input type="hidden" name="state" value="STATE">
  <input type="hidden" name="iss" value="ISSUER">
</form>
<script>document.forms[0].submit()</script>
```

This is the most secure mode because:

* Authorization code not in browser history
* Code not logged in server access logs
* Code not leaked via Referer header

## Prompt Parameter

Control user interaction:

| Value | Behavior |
|-------|----------|
| none | Silent authentication. Returns error if login/consent needed |
| login | Force re-authentication |
| consent | Force consent screen |

Errors for `prompt=none`:

* `login_required` - User must authenticate
* `consent_required` - User must grant consent
* `interaction_required` - Some interaction needed
