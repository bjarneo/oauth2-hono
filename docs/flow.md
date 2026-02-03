# OAuth 2.0 Flow Diagrams

This document provides visual representations of the OAuth 2.0 flows supported by this authorization server.

## Table of Contents

- [Request Routing (Multi-Tenant)](#request-routing-multi-tenant)
- [Authorization Code Flow with PKCE](#authorization-code-flow-with-pkce)
- [Client Credentials Flow](#client-credentials-flow)
- [Refresh Token Flow](#refresh-token-flow)
- [Device Authorization Flow](#device-authorization-flow)
- [Token Introspection](#token-introspection)
- [Token Revocation](#token-revocation)

---

## Request Routing (Multi-Tenant)

All requests are routed through tenant-specific paths. The tenant resolver middleware extracts and validates the tenant before processing any OAuth request.

```mermaid
flowchart TD
    A[Incoming Request] --> B{Extract Tenant Slug<br/>from URL path}
    B --> C["/:tenant/authorize<br/>/:tenant/token<br/>/:tenant/.well-known/*"]
    C --> D{Tenant Exists?}
    D -->|No| E[400 Invalid Request]
    D -->|Yes| F{Tenant Enabled?}
    F -->|No| G[400 Tenant Disabled]
    F -->|Yes| H[Set Tenant in Context]
    H --> I[Continue to Route Handler]

    style A fill:#e1f5fe
    style E fill:#ffcdd2
    style G fill:#ffcdd2
    style I fill:#c8e6c9
```

---

## Authorization Code Flow with PKCE

The recommended flow for web applications and native apps. PKCE (Proof Key for Code Exchange) is required for all authorization code requests per RFC 9700.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client App
    participant Browser as User's Browser
    participant AuthServer as Authorization Server
    participant User as Resource Owner

    Note over Client: Generate PKCE values
    Client->>Client: code_verifier = random(43-128 chars)
    Client->>Client: code_challenge = BASE64URL(SHA256(code_verifier))

    Client->>Browser: Redirect to authorization endpoint

    Browser->>AuthServer: GET /{tenant}/authorize<br/>?response_type=code<br/>&client_id=xxx<br/>&redirect_uri=xxx<br/>&scope=openid profile<br/>&state=xxx<br/>&code_challenge=xxx<br/>&code_challenge_method=S256

    AuthServer->>AuthServer: Validate client & redirect_uri

    AuthServer->>User: Present login form
    User->>AuthServer: Authenticate (username/password)

    AuthServer->>User: Present consent screen
    User->>AuthServer: Grant consent

    AuthServer->>AuthServer: Generate authorization code
    AuthServer->>Browser: Redirect to redirect_uri<br/>?code=xxx&state=xxx

    Browser->>Client: Authorization code + state

    Client->>AuthServer: POST /{tenant}/token<br/>grant_type=authorization_code<br/>&code=xxx<br/>&redirect_uri=xxx<br/>&code_verifier=xxx<br/>&client_id=xxx

    AuthServer->>AuthServer: Verify code_verifier against<br/>stored code_challenge
    AuthServer->>AuthServer: Validate code (single-use, not expired)
    AuthServer->>AuthServer: Generate tokens

    AuthServer->>Client: {<br/>  access_token: "xxx",<br/>  token_type: "Bearer",<br/>  expires_in: 3600,<br/>  refresh_token: "xxx",<br/>  id_token: "xxx",<br/>  scope: "openid profile"<br/>}
```

### PKCE Verification Detail

```mermaid
flowchart LR
    A[code_verifier] --> B[SHA-256 Hash]
    B --> C[Base64URL Encode]
    C --> D[Computed Challenge]
    D --> E{Matches stored<br/>code_challenge?}
    E -->|Yes| F[✓ Valid]
    E -->|No| G[✗ Invalid]

    style F fill:#c8e6c9
    style G fill:#ffcdd2
```

---

## Client Credentials Flow

For machine-to-machine authentication where no user context is needed.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Backend Service
    participant AuthServer as Authorization Server
    participant Resource as Protected Resource

    Note over Client: Confidential client<br/>(has client_secret)

    alt Basic Authentication
        Client->>AuthServer: POST /{tenant}/token<br/>Authorization: Basic base64(client_id:client_secret)<br/>grant_type=client_credentials<br/>&scope=api:read api:write
    else POST Body Authentication
        Client->>AuthServer: POST /{tenant}/token<br/>grant_type=client_credentials<br/>&client_id=xxx<br/>&client_secret=xxx<br/>&scope=api:read api:write
    else Private Key JWT
        Client->>Client: Sign JWT assertion with private key
        Client->>AuthServer: POST /{tenant}/token<br/>grant_type=client_credentials<br/>&client_id=xxx<br/>&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer<br/>&client_assertion=xxx
    end

    AuthServer->>AuthServer: Authenticate client
    AuthServer->>AuthServer: Validate requested scopes<br/>against allowed scopes
    AuthServer->>AuthServer: Generate access token (JWT)

    AuthServer->>Client: {<br/>  access_token: "xxx",<br/>  token_type: "Bearer",<br/>  expires_in: 3600,<br/>  scope: "api:read api:write"<br/>}

    Client->>Resource: Request with Bearer token
    Resource->>Resource: Validate JWT signature<br/>Check expiration & claims
    Resource->>Client: Protected resource data
```

---

## Refresh Token Flow

Obtain new access tokens without user interaction. Implements rotation for security.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client App
    participant AuthServer as Authorization Server

    Note over Client: Access token expired<br/>or about to expire

    Client->>AuthServer: POST /{tenant}/token<br/>grant_type=refresh_token<br/>&refresh_token=xxx<br/>&client_id=xxx<br/>&client_secret=xxx (if confidential)

    AuthServer->>AuthServer: Validate refresh token

    alt Token Valid
        AuthServer->>AuthServer: Revoke old refresh token
        AuthServer->>AuthServer: Generate new token pair
        AuthServer->>Client: {<br/>  access_token: "new_xxx",<br/>  token_type: "Bearer",<br/>  expires_in: 3600,<br/>  refresh_token: "new_yyy"<br/>}
    else Token Reused (Replay Attack)
        AuthServer->>AuthServer: Detect reuse via family_id
        AuthServer->>AuthServer: Revoke entire token family
        AuthServer->>Client: 400 invalid_grant<br/>"Token has been revoked"
    else Token Expired/Invalid
        AuthServer->>Client: 400 invalid_grant
    end
```

### Token Rotation & Replay Detection

```mermaid
flowchart TD
    A[Refresh Token Request] --> B{Token exists?}
    B -->|No| C[Invalid Grant]
    B -->|Yes| D{Already revoked?}
    D -->|Yes| E[Replay Attack Detected!]
    E --> F[Revoke ALL tokens<br/>in family]
    F --> C
    D -->|No| G{Expired?}
    G -->|Yes| C
    G -->|No| H[Revoke current token]
    H --> I[Create new token pair<br/>with same family_id]
    I --> J[Return new tokens]

    style C fill:#ffcdd2
    style E fill:#ff8a80
    style J fill:#c8e6c9
```

---

## Device Authorization Flow

For devices with limited input capabilities (TVs, CLI tools, IoT devices). Implements RFC 8628.

```mermaid
sequenceDiagram
    autonumber
    participant Device as Device/CLI
    participant AuthServer as Authorization Server
    participant Browser as User's Browser
    participant User as User

    Device->>AuthServer: POST /{tenant}/device/authorize<br/>client_id=xxx<br/>&scope=openid profile

    AuthServer->>AuthServer: Generate device_code<br/>and user_code

    AuthServer->>Device: {<br/>  device_code: "xxx",<br/>  user_code: "ABCD-1234",<br/>  verification_uri: "https://auth.example.com/device",<br/>  verification_uri_complete: "https://auth.example.com/device?user_code=ABCD-1234",<br/>  expires_in: 600,<br/>  interval: 5<br/>}

    Note over Device: Display user_code and<br/>verification_uri to user

    par User Authorization
        User->>Browser: Navigate to verification_uri
        Browser->>AuthServer: GET /device
        AuthServer->>User: Enter user code
        User->>AuthServer: Submit "ABCD-1234"
        AuthServer->>User: Login prompt
        User->>AuthServer: Authenticate
        AuthServer->>User: Consent screen
        User->>AuthServer: Approve
        AuthServer->>AuthServer: Mark device_code as authorized
        AuthServer->>User: Success message
    and Device Polling
        loop Every {interval} seconds
            Device->>AuthServer: POST /{tenant}/token<br/>grant_type=urn:ietf:params:oauth:grant-type:device_code<br/>&device_code=xxx<br/>&client_id=xxx
            alt Still Pending
                AuthServer->>Device: 400 authorization_pending
            else User Denied
                AuthServer->>Device: 403 access_denied
            else Too Fast
                AuthServer->>Device: 400 slow_down
            else Expired
                AuthServer->>Device: 400 expired_token
            else Authorized
                AuthServer->>Device: {<br/>  access_token: "xxx",<br/>  token_type: "Bearer",<br/>  refresh_token: "xxx"<br/>}
            end
        end
    end
```

### Device Code States

```mermaid
stateDiagram-v2
    [*] --> pending: Device requests code
    pending --> authorized: User approves
    pending --> denied: User denies
    pending --> expired: Timeout (600s)
    authorized --> [*]: Tokens issued
    denied --> [*]: Access denied error
    expired --> [*]: Expired token error
```

---

## Token Introspection

Allows resource servers to validate tokens and retrieve metadata. Implements RFC 7662.

```mermaid
sequenceDiagram
    autonumber
    participant Resource as Resource Server
    participant AuthServer as Authorization Server

    Note over Resource: Received access_token<br/>from client request

    Resource->>AuthServer: POST /{tenant}/introspect<br/>Authorization: Basic base64(client_id:client_secret)<br/>token=xxx<br/>&token_type_hint=access_token

    AuthServer->>AuthServer: Authenticate resource server
    AuthServer->>AuthServer: Decode & validate token

    alt Token Valid
        AuthServer->>Resource: {<br/>  active: true,<br/>  client_id: "xxx",<br/>  username: "user@example.com",<br/>  scope: "openid profile",<br/>  sub: "user-123",<br/>  aud: "https://api.example.com",<br/>  iss: "https://auth.example.com/tenant",<br/>  exp: 1234567890,<br/>  iat: 1234564290<br/>}
    else Token Invalid/Expired/Revoked
        AuthServer->>Resource: {<br/>  active: false<br/>}
    end
```

---

## Token Revocation

Allows clients to invalidate tokens. Implements RFC 7009.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client App
    participant AuthServer as Authorization Server

    Note over Client: User logs out or<br/>token compromised

    Client->>AuthServer: POST /{tenant}/revoke<br/>Authorization: Basic base64(client_id:client_secret)<br/>token=xxx<br/>&token_type_hint=refresh_token

    AuthServer->>AuthServer: Authenticate client
    AuthServer->>AuthServer: Identify token type

    alt Refresh Token
        AuthServer->>AuthServer: Revoke token<br/>Mark as revoked in storage
    else Access Token (JWT)
        AuthServer->>AuthServer: Add jti to revocation list<br/>(tracked until original expiry)
    end

    AuthServer->>Client: 200 OK<br/>(always success per RFC)
```

---

## Complete System Overview

```mermaid
flowchart TB
    subgraph Clients
        WebApp[Web Application]
        Mobile[Mobile App]
        CLI[CLI Tool]
        Backend[Backend Service]
    end

    subgraph AuthServer[Authorization Server]
        direction TB

        subgraph Middleware
            TenantResolver[Tenant Resolver]
            RateLimiter[Rate Limiter]
            ClientAuth[Client Authenticator]
            BearerAuth[Bearer Auth]
        end

        subgraph Endpoints
            Authorize["/authorize"]
            Token["/token"]
            Introspect["/introspect"]
            Revoke["/revoke"]
            DeviceAuth["/device/authorize"]
            JWKS["/.well-known/jwks.json"]
            Discovery["/.well-known/openid-configuration"]
        end

        subgraph Grants
            AuthCode[Authorization Code]
            ClientCreds[Client Credentials]
            RefreshToken[Refresh Token]
            DeviceCode[Device Code]
        end

        subgraph Storage
            TenantStore[(Tenants)]
            ClientStore[(Clients)]
            TokenStore[(Tokens)]
            CodeStore[(Auth Codes)]
        end
    end

    subgraph ResourceServers[Resource Servers]
        API1[API Service 1]
        API2[API Service 2]
    end

    WebApp --> Authorize
    Mobile --> Authorize
    CLI --> DeviceAuth
    Backend --> Token

    Authorize --> AuthCode
    Token --> ClientCreds
    Token --> RefreshToken
    Token --> DeviceCode

    AuthCode --> TokenStore
    ClientCreds --> TokenStore
    RefreshToken --> TokenStore
    DeviceCode --> TokenStore

    API1 --> Introspect
    API2 --> BearerAuth
    BearerAuth --> JWKS

    style AuthServer fill:#e3f2fd
    style Middleware fill:#fff3e0
    style Endpoints fill:#e8f5e9
    style Grants fill:#fce4ec
    style Storage fill:#f3e5f5
```

---

## Client Authentication Methods

```mermaid
flowchart TD
    A[Token Request] --> B{Check Auth Header}

    B -->|Basic Auth Present| C[client_secret_basic]
    C --> D[Decode Base64<br/>Extract client_id:client_secret]
    D --> E[Verify against stored hash]

    B -->|No Header| F{Check POST Body}

    F -->|client_assertion present| G[private_key_jwt]
    G --> H[Fetch JWKS<br/>from client.jwks_uri]
    H --> I[Verify JWT signature<br/>Check iss, aud, exp]

    F -->|client_secret present| J[client_secret_post]
    J --> K[Verify against stored hash]

    F -->|client_id only| L{Client allows none?}
    L -->|Yes| M[Public Client<br/>auth_method=none]
    L -->|No| N[Error: Credentials Required]

    E --> O[Authenticated]
    I --> O
    K --> O
    M --> O

    style O fill:#c8e6c9
    style N fill:#ffcdd2
```

---

## JWT Access Token Structure

```mermaid
flowchart LR
    subgraph Header
        A[alg: RS256<br/>typ: at+jwt<br/>kid: key-id]
    end

    subgraph Payload
        B["iss: issuer URL<br/>sub: user or client ID<br/>aud: audience<br/>exp: expiration<br/>iat: issued at<br/>jti: unique ID<br/>client_id: xxx<br/>scope: openid profile<br/>tenant_id: xxx"]
    end

    subgraph Signature
        C[RSA-SHA256<br/>signed with<br/>tenant private key]
    end

    Header --> Payload --> Signature
```

---

## Error Response Flow

```mermaid
flowchart TD
    A[OAuth Error Occurs] --> B{Error Type}

    B -->|invalid_request| C[400 Bad Request<br/>Missing/invalid parameters]
    B -->|invalid_client| D[401 Unauthorized<br/>Client authentication failed]
    B -->|invalid_grant| E[400 Bad Request<br/>Invalid code/token]
    B -->|unauthorized_client| F[400 Bad Request<br/>Client not allowed for grant]
    B -->|unsupported_grant_type| G[400 Bad Request<br/>Grant type not supported]
    B -->|invalid_scope| H[400 Bad Request<br/>Scope not allowed]
    B -->|access_denied| I[403 Forbidden<br/>User denied consent]
    B -->|server_error| J[500 Internal Error<br/>Unexpected error]

    C --> K[JSON Response:<br/>error: error_code<br/>error_description: message]
    D --> K
    E --> K
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K
```
