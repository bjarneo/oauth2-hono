# Identity Provider Federation

This document describes how to configure and use identity provider federation to enable social login and enterprise SSO.

## Overview

Identity provider federation allows users to authenticate using their existing accounts from external providers like Google, GitHub, or Microsoft. The server acts as a relying party to these external identity providers and handles the OAuth/OIDC flow on behalf of your application.

## Supported Providers

The server includes pre-configured templates for common providers:

| Provider | Type | Template ID |
|----------|------|-------------|
| Google | OIDC | `google` |
| GitHub | OAuth 2.0 | `github` |
| Microsoft | OIDC | `microsoft` |
| Apple | OIDC | `apple` |
| Facebook | OAuth 2.0 | `facebook` |
| Twitter | OAuth 2.0 | `twitter` |
| LinkedIn | OIDC | `linkedin` |

For other providers, use `generic_oidc` for OpenID Connect providers or `generic_oauth2` for standard OAuth 2.0 providers.

## Configuration

### Creating an Identity Provider

Use the admin API or admin panel to create an identity provider configuration.

```bash
curl -X POST http://localhost:3000/_admin/tenants/TENANT_ID/identity-providers \
  -H "X-Admin-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Google",
    "slug": "google",
    "template": "google",
    "clientId": "your-google-client-id.apps.googleusercontent.com",
    "clientSecret": "your-google-client-secret",
    "scopes": ["openid", "profile", "email"],
    "enabled": true
  }'
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| name | Yes | Display name for the provider |
| slug | Yes | URL-safe identifier used in federation URLs |
| template | No | Pre-configured template (google, github, etc.) |
| type | No | Provider type: `oidc`, `oauth2`, or `saml` |
| clientId | Yes | OAuth client ID from the provider |
| clientSecret | Yes | OAuth client secret from the provider |
| issuer | No | OIDC issuer URL (auto-configured for templates) |
| authorizationEndpoint | No | Authorization URL (auto-configured for templates) |
| tokenEndpoint | No | Token URL (auto-configured for templates) |
| userinfoEndpoint | No | UserInfo URL (auto-configured for templates) |
| jwksUri | No | JWKS URL for token verification |
| scopes | No | OAuth scopes to request |
| attributeMapping | No | Map provider attributes to local user fields |
| enabled | No | Whether the provider is active (default: true) |
| displayOrder | No | Sort order for displaying providers |
| iconUrl | No | URL for provider icon |
| buttonText | No | Custom button text (e.g., "Sign in with Google") |

### Generic OIDC Provider

For providers not covered by templates, use `generic_oidc` and provide the endpoints:

```json
{
  "name": "Corporate SSO",
  "slug": "corporate-sso",
  "type": "oidc",
  "clientId": "your-client-id",
  "clientSecret": "your-client-secret",
  "issuer": "https://sso.example.com",
  "authorizationEndpoint": "https://sso.example.com/authorize",
  "tokenEndpoint": "https://sso.example.com/token",
  "userinfoEndpoint": "https://sso.example.com/userinfo",
  "scopes": ["openid", "profile", "email"]
}
```

## Federation Flow

### Step 1: Initiate Authentication

Redirect users to the federation initiation endpoint:

```
GET /<tenant>/federate/<idp_slug>
```

Optional query parameters:

| Parameter | Description |
|-----------|-------------|
| state | Opaque state value passed through the flow |
| redirect_uri | URL to redirect after authentication |
| client_id | Original OAuth client ID (for tracking) |
| scope | Requested scopes |
| nonce | Nonce for OIDC ID token verification |

Example:

```
http://localhost:3000/dev/federate/google?
  state=abc123&
  redirect_uri=http://localhost:3001/callback
```

### Step 2: External Authentication

The server redirects the user to the external provider's authorization endpoint. The user authenticates with the provider.

### Step 3: Callback Handling

After authentication, the provider redirects to:

```
GET /<tenant>/federate/<idp_slug>/callback
```

The server:

1. Validates the state parameter
2. Exchanges the authorization code for tokens
3. Fetches user information from the provider
4. Creates or updates a federated identity record
5. Returns the result or redirects to the specified redirect_uri

### Step 4: Response

If a redirect_uri was provided, the user is redirected with:

```
http://localhost:3001/callback?
  federated_user_id=user-123&
  provider=google&
  state=abc123
```

If no redirect_uri was provided, a JSON response is returned:

```json
{
  "success": true,
  "user_id": "federated:google:123456789",
  "is_new_user": false,
  "provider": "google",
  "provider_user_id": "123456789",
  "user_data": {
    "email": "user@example.com",
    "name": "John Doe",
    "picture": "https://..."
  }
}
```

## Attribute Mapping

Attribute mapping defines how provider user attributes map to local user fields.

### Default Mappings

Templates include sensible default mappings. For example, Google:

```json
{
  "id": "sub",
  "email": "email",
  "name": "name",
  "givenName": "given_name",
  "familyName": "family_name",
  "picture": "picture",
  "emailVerified": "email_verified"
}
```

### Custom Mappings

Override mappings by providing an `attributeMapping` object:

```json
{
  "attributeMapping": {
    "id": "user_id",
    "email": "contact.email",
    "name": "profile.full_name",
    "picture": "profile.avatar_url"
  }
}
```

The mapping values support dot notation for nested attributes.

## Custom Login Handling

To customize how federated logins are processed, provide an `onFederatedLogin` callback:

```typescript
const server = createOAuth2Server({
  storage,
  federation: {
    enabled: true,
    onFederatedLogin: async ({
      tenantId,
      providerId,
      providerUserId,
      providerUserData,
    }) => {
      // Look up or create a user in your user database
      let user = await userService.findByFederatedIdentity(
        tenantId,
        providerId,
        providerUserId
      );

      if (!user) {
        // Create a new user from the provider data
        user = await userService.create({
          email: providerUserData.email,
          name: providerUserData.name,
        });

        // Link the federated identity
        await storage.federatedIdentities.create({
          tenantId,
          userId: user.id,
          providerId,
          providerUserId,
          providerUserData,
        });

        return { userId: user.id, isNewUser: true };
      }

      // Update provider data
      await storage.federatedIdentities.update(existingLink.id, {
        providerUserData,
      });

      return { userId: user.id, isNewUser: false };
    },
  },
});
```

## Security Considerations

### Client Secret Storage

Client secrets are encrypted at rest using AES-256-GCM. Set the `ENCRYPTION_KEY` environment variable in production:

```bash
ENCRYPTION_KEY=your-32-byte-encryption-key
```

If not set, a default development key is used (not secure for production).

### State Validation

The federation flow uses cryptographically random state values to prevent CSRF attacks. State values expire after 10 minutes.

### Token Handling

Provider access tokens and refresh tokens are not stored by default. They are used only during the callback to fetch user information. If you need to store them for API access, implement this in your `onFederatedLogin` callback.

## Provider Setup Guides

### Google

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to APIs & Services > Credentials
4. Create an OAuth 2.0 Client ID
5. Add authorized redirect URI: `http://localhost:3000/<tenant>/federate/google/callback`
6. Copy the Client ID and Client Secret

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Set the callback URL to: `http://localhost:3000/<tenant>/federate/github/callback`
4. Copy the Client ID and generate a Client Secret

### Microsoft

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Create a new registration
4. Add redirect URI: `http://localhost:3000/<tenant>/federate/microsoft/callback`
5. Create a client secret under Certificates & secrets
6. Copy the Application (client) ID and secret value

## Troubleshooting

### Invalid State Error

This occurs when:
* The state parameter expired (over 10 minutes)
* The state was already used (one-time use)
* The browser has multiple tabs with different flows

Solution: Retry the authentication flow from the beginning.

### Token Exchange Failed

Check that:
* The client ID and secret are correct
* The redirect URI matches exactly (including trailing slashes)
* The provider's OAuth app is properly configured

### Missing User Information

Some providers require additional scopes or permissions to return certain user data. Check the provider's documentation for required scopes.

### GitHub Email Not Available

GitHub requires the `user:email` scope and may return null if the user's email is private. The server automatically fetches the email from the `/user/emails` endpoint when using the GitHub template.
