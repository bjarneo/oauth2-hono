import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import {
  BookOpen,
  Code,
  Key,
  Lock,
  RefreshCw,
  Shield,
  Users,
  Zap,
  CheckCircle,
  AlertCircle,
  ArrowRight,
  Copy,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

function CodeBlock({ children }: { children: string }) {
  const copyToClipboard = () => {
    navigator.clipboard.writeText(children);
    toast({ title: 'Copied to clipboard' });
  };

  return (
    <div className="relative group">
      <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto">
        <code>{children}</code>
      </pre>
      <Button
        variant="ghost"
        size="icon"
        className="absolute top-2 right-2 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={copyToClipboard}
      >
        <Copy className="h-3 w-3" />
      </Button>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-3">
      <h3 className="text-lg font-semibold">{title}</h3>
      {children}
    </div>
  );
}

function Tip({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 p-3 bg-primary/10 rounded-md text-sm">
      <CheckCircle className="h-4 w-4 text-primary mt-0.5 shrink-0" />
      <div>{children}</div>
    </div>
  );
}

function Warning({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 p-3 bg-destructive/10 rounded-md text-sm">
      <AlertCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
      <div>{children}</div>
    </div>
  );
}

function OverviewTab() {
  return (
    <div className="space-y-6">
      <Section title="What is OAuth 2.0?">
        <p className="text-muted-foreground">
          OAuth 2.0 is an authorization framework that enables applications to obtain limited access
          to user accounts on third-party services. Instead of sharing passwords, users grant
          applications access tokens that define what the application can do.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Secure
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              Users never share their passwords with third-party applications.
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Key className="h-4 w-4" />
                Scoped Access
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              Applications only get access to specific resources they need.
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <RefreshCw className="h-4 w-4" />
                Revocable
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              Users can revoke access at any time without changing their password.
            </CardContent>
          </Card>
        </div>
      </Section>

      <Separator />

      <Section title="Key Concepts">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <h4 className="font-medium flex items-center gap-2">
                <Users className="h-4 w-4" />
                Resource Owner
              </h4>
              <p className="text-sm text-muted-foreground">
                The user who owns the data and grants access to it. For example, you are the
                resource owner of your GitHub repositories.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium flex items-center gap-2">
                <Code className="h-4 w-4" />
                Client
              </h4>
              <p className="text-sm text-muted-foreground">
                The application requesting access to protected resources. This could be a web app,
                mobile app, or backend service.
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium flex items-center gap-2">
                <Lock className="h-4 w-4" />
                Authorization Server
              </h4>
              <p className="text-sm text-muted-foreground">
                The server that authenticates users and issues access tokens. That's what this
                server is!
              </p>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium flex items-center gap-2">
                <Zap className="h-4 w-4" />
                Resource Server
              </h4>
              <p className="text-sm text-muted-foreground">
                The API server that hosts protected resources. It validates access tokens before
                serving requests.
              </p>
            </div>
          </div>
        </div>
      </Section>

      <Separator />

      <Section title="What is OpenID Connect (OIDC)?">
        <p className="text-muted-foreground">
          OpenID Connect is an identity layer built on top of OAuth 2.0. While OAuth 2.0 is about
          authorization (what you can access), OIDC adds authentication (who you are).
        </p>
        <div className="mt-4 space-y-2">
          <div className="flex items-start gap-2">
            <Badge variant="outline" className="mt-0.5">OAuth 2.0</Badge>
            <span className="text-sm">Grants access to resources (authorization)</span>
          </div>
          <div className="flex items-start gap-2">
            <Badge variant="default" className="mt-0.5">OIDC</Badge>
            <span className="text-sm">Verifies user identity + grants access (authentication + authorization)</span>
          </div>
        </div>
        <Tip>
          If you need to know who the user is (login), use OIDC with the <code className="text-xs bg-muted px-1 rounded">openid</code> scope.
          If you only need to access an API, OAuth 2.0 alone is sufficient.
        </Tip>
      </Section>
    </div>
  );
}

function GrantTypesTab() {
  return (
    <div className="space-y-6">
      <p className="text-muted-foreground">
        Grant types define how a client application obtains an access token. Choose the right grant
        type based on your application type and security requirements.
      </p>

      <Accordion type="single" collapsible className="w-full">
        <AccordionItem value="authorization-code">
          <AccordionTrigger>
            <div className="flex items-center gap-2">
              <Badge variant="success">Recommended</Badge>
              Authorization Code Grant
            </div>
          </AccordionTrigger>
          <AccordionContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              The most secure grant type for web and mobile applications. Users authenticate
              directly with the authorization server, and the client receives a code that it
              exchanges for tokens.
            </p>

            <div className="space-y-2">
              <h4 className="font-medium">When to use:</h4>
              <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                <li>Web applications with a backend</li>
                <li>Mobile applications</li>
                <li>Single-page applications (with PKCE)</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Flow:</h4>
              <div className="flex items-center gap-2 text-sm flex-wrap">
                <Badge variant="outline">1. User clicks login</Badge>
                <ArrowRight className="h-4 w-4" />
                <Badge variant="outline">2. Redirect to /authorize</Badge>
                <ArrowRight className="h-4 w-4" />
                <Badge variant="outline">3. User authenticates</Badge>
                <ArrowRight className="h-4 w-4" />
                <Badge variant="outline">4. Redirect with code</Badge>
                <ArrowRight className="h-4 w-4" />
                <Badge variant="outline">5. Exchange code for tokens</Badge>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Step 1: Redirect to Authorization</h4>
              <CodeBlock>{`GET /dev/authorize?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=http://localhost:3001/callback
  &scope=openid profile email
  &state=random_state_value
  &code_challenge=BASE64_CHALLENGE
  &code_challenge_method=S256`}</CodeBlock>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Step 2: Exchange Code for Tokens</h4>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=AUTHORIZATION_CODE" \\
  -d "redirect_uri=http://localhost:3001/callback" \\
  -d "client_id=YOUR_CLIENT_ID" \\
  -d "client_secret=YOUR_CLIENT_SECRET" \\
  -d "code_verifier=ORIGINAL_VERIFIER"`}</CodeBlock>
            </div>

            <Tip>
              Always use PKCE (Proof Key for Code Exchange) even for confidential clients. It
              provides an extra layer of security against authorization code interception attacks.
            </Tip>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="client-credentials">
          <AccordionTrigger>
            <div className="flex items-center gap-2">
              <Badge variant="secondary">Machine-to-Machine</Badge>
              Client Credentials Grant
            </div>
          </AccordionTrigger>
          <AccordionContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Used for server-to-server communication where no user is involved. The client
              authenticates with its own credentials to access resources it owns or has been
              granted access to.
            </p>

            <div className="space-y-2">
              <h4 className="font-medium">When to use:</h4>
              <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                <li>Backend services calling APIs</li>
                <li>Cron jobs and scheduled tasks</li>
                <li>Microservices communication</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Example Request:</h4>
              <CodeBlock>{`# Using HTTP Basic Authentication
curl -X POST http://localhost:3000/dev/token \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=client_credentials" \\
  -d "scope=api:read api:write"`}</CodeBlock>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Alternative: POST body authentication</h4>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=client_credentials" \\
  -d "client_id=YOUR_CLIENT_ID" \\
  -d "client_secret=YOUR_CLIENT_SECRET" \\
  -d "scope=api:read"`}</CodeBlock>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Response:</h4>
              <CodeBlock>{`{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}`}</CodeBlock>
            </div>

            <Warning>
              Never expose client credentials in frontend code. This grant type is only for
              confidential clients that can securely store secrets.
            </Warning>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="refresh-token">
          <AccordionTrigger>
            <div className="flex items-center gap-2">
              <Badge variant="outline">Token Renewal</Badge>
              Refresh Token Grant
            </div>
          </AccordionTrigger>
          <AccordionContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Used to obtain a new access token without requiring the user to re-authenticate.
              Refresh tokens are long-lived and should be stored securely.
            </p>

            <div className="space-y-2">
              <h4 className="font-medium">When to use:</h4>
              <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                <li>When an access token expires</li>
                <li>To maintain long user sessions</li>
                <li>Mobile apps that need offline access</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Example Request:</h4>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/token \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=refresh_token" \\
  -d "refresh_token=YOUR_REFRESH_TOKEN"`}</CodeBlock>
            </div>

            <Tip>
              Request the <code className="text-xs bg-muted px-1 rounded">offline_access</code> scope
              during initial authorization to receive a refresh token.
            </Tip>

            <Warning>
              Refresh tokens are powerful. Store them securely (encrypted at rest) and implement
              refresh token rotation for maximum security.
            </Warning>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="device-code">
          <AccordionTrigger>
            <div className="flex items-center gap-2">
              <Badge variant="outline">Input-Constrained Devices</Badge>
              Device Code Grant
            </div>
          </AccordionTrigger>
          <AccordionContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Designed for devices that have limited input capabilities (smart TVs, CLI tools,
              IoT devices). The user authorizes the device using a separate device like their phone.
            </p>

            <div className="space-y-2">
              <h4 className="font-medium">When to use:</h4>
              <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                <li>Smart TVs and streaming devices</li>
                <li>CLI applications</li>
                <li>IoT devices without keyboards</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Step 1: Request Device Code</h4>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/device_authorization \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=YOUR_CLIENT_ID" \\
  -d "scope=openid profile"`}</CodeBlock>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Response:</h4>
              <CodeBlock>{`{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "http://localhost:3000/dev/device",
  "verification_uri_complete": "http://localhost:3000/dev/device?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}`}</CodeBlock>
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Step 2: Poll for Token</h4>
              <CodeBlock>{`# Poll every 'interval' seconds until user authorizes
curl -X POST http://localhost:3000/dev/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \\
  -d "device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS" \\
  -d "client_id=YOUR_CLIENT_ID"`}</CodeBlock>
            </div>

            <Tip>
              Display the user_code prominently and provide clear instructions for the user to
              visit the verification_uri on their phone or computer.
            </Tip>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  );
}

function TokensTab() {
  return (
    <div className="space-y-6">
      <Section title="Token Types">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Key className="h-4 w-4" />
                Access Token
              </CardTitle>
              <CardDescription>Short-lived credential for API access</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Access tokens are credentials used to access protected resources. They are typically
                short-lived (1 hour) and should be included in API requests.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Using an Access Token:</h4>
                <CodeBlock>{`curl -X GET http://api.example.com/user \\
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`}</CodeBlock>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">JWT Structure:</h4>
                <CodeBlock>{`{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id-123"
  },
  "payload": {
    "iss": "http://localhost:3000/dev",
    "sub": "user-123",
    "aud": "client-id",
    "exp": 1234567890,
    "iat": 1234564290,
    "scope": "openid profile email"
  }
}`}</CodeBlock>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <RefreshCw className="h-4 w-4" />
                Refresh Token
              </CardTitle>
              <CardDescription>Long-lived credential for obtaining new access tokens</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Refresh tokens are used to obtain new access tokens without user interaction. They
                have a longer lifetime (30 days default) and should be stored securely.
              </p>
              <Warning>
                Refresh tokens are sensitive. Never expose them in URLs, logs, or client-side code.
                Use secure, encrypted storage.
              </Warning>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Users className="h-4 w-4" />
                ID Token (OIDC)
              </CardTitle>
              <CardDescription>JWT containing user identity information</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                ID tokens are JWTs that contain claims about the authenticated user. They are only
                issued when the <code className="text-xs bg-muted px-1 rounded">openid</code> scope
                is requested.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">ID Token Claims:</h4>
                <CodeBlock>{`{
  "iss": "http://localhost:3000/dev",
  "sub": "user-123",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234564290,
  "nonce": "abc123",
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true
}`}</CodeBlock>
              </div>
              <Tip>
                ID tokens are meant for the client application. Never send them to your API.
                Use access tokens for API authentication.
              </Tip>
            </CardContent>
          </Card>
        </div>
      </Section>

      <Separator />

      <Section title="Token Validation">
        <p className="text-muted-foreground">
          There are two ways to validate tokens: local validation and introspection.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Local Validation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">Validate JWT tokens locally using the public key.</p>
              <ol className="list-decimal list-inside space-y-1 text-muted-foreground">
                <li>Fetch JWKS from <code className="text-xs bg-muted px-1 rounded">/.well-known/jwks.json</code></li>
                <li>Verify the JWT signature</li>
                <li>Check expiration (exp claim)</li>
                <li>Validate issuer and audience</li>
              </ol>
              <Badge variant="success">Fast, no network call</Badge>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Token Introspection</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">Query the authorization server for token status.</p>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/introspect \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -d "token=ACCESS_TOKEN"`}</CodeBlock>
              <Badge variant="outline">Real-time status, supports revocation</Badge>
            </CardContent>
          </Card>
        </div>
      </Section>
    </div>
  );
}

function ScopesTab() {
  return (
    <div className="space-y-6">
      <Section title="What are Scopes?">
        <p className="text-muted-foreground">
          Scopes define what access the client is requesting. They limit what the access token can
          be used for, following the principle of least privilege.
        </p>
      </Section>

      <Section title="Standard OIDC Scopes">
        <div className="space-y-3">
          <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-3 font-medium">Scope</th>
                  <th className="text-left p-3 font-medium">Description</th>
                  <th className="text-left p-3 font-medium">Claims Returned</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">openid</code></td>
                  <td className="p-3 text-muted-foreground">Required for OIDC. Returns an ID token.</td>
                  <td className="p-3 text-muted-foreground">sub</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">profile</code></td>
                  <td className="p-3 text-muted-foreground">Basic profile information</td>
                  <td className="p-3 text-muted-foreground">name, family_name, given_name, picture, etc.</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">email</code></td>
                  <td className="p-3 text-muted-foreground">Email address</td>
                  <td className="p-3 text-muted-foreground">email, email_verified</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">offline_access</code></td>
                  <td className="p-3 text-muted-foreground">Request a refresh token</td>
                  <td className="p-3 text-muted-foreground">Returns refresh_token</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      <Section title="Custom Scopes">
        <p className="text-muted-foreground">
          You can define custom scopes for your APIs. Common patterns include:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Resource-based</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              <code className="bg-muted px-1 rounded">api:read</code>{' '}
              <code className="bg-muted px-1 rounded">api:write</code>{' '}
              <code className="bg-muted px-1 rounded">users:admin</code>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Service-based</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              <code className="bg-muted px-1 rounded">billing:read</code>{' '}
              <code className="bg-muted px-1 rounded">inventory:write</code>{' '}
              <code className="bg-muted px-1 rounded">reports:generate</code>
            </CardContent>
          </Card>
        </div>
        <Tip>
          Configure allowed scopes at the tenant level and per-client. Clients can only request
          scopes they are authorized to use.
        </Tip>
      </Section>

      <Section title="Requesting Scopes">
        <CodeBlock>{`# Request specific scopes during authorization
GET /dev/authorize?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=http://localhost:3001/callback
  &scope=openid profile email offline_access api:read
  &state=xyz`}</CodeBlock>
        <p className="text-sm text-muted-foreground mt-2">
          The authorization server will only grant scopes that:
        </p>
        <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1 mt-2">
          <li>Are enabled for the tenant</li>
          <li>Are allowed for the client</li>
          <li>The user consents to (if consent is required)</li>
        </ul>
      </Section>
    </div>
  );
}

function EndpointsTab() {
  return (
    <div className="space-y-6">
      <Section title="Discovery Endpoint">
        <p className="text-muted-foreground">
          The OpenID Connect discovery endpoint provides all the information needed to interact
          with the authorization server.
        </p>
        <CodeBlock>{`curl http://localhost:3000/dev/.well-known/openid-configuration | jq`}</CodeBlock>
        <Tip>
          Always use the discovery endpoint to get URLs dynamically. This makes your integration
          more resilient to configuration changes.
        </Tip>
      </Section>

      <Section title="Core Endpoints">
        <div className="space-y-4">
          <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-3 font-medium">Endpoint</th>
                  <th className="text-left p-3 font-medium">Method</th>
                  <th className="text-left p-3 font-medium">Purpose</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/authorize</code></td>
                  <td className="p-3">GET</td>
                  <td className="p-3 text-muted-foreground">Start authorization flow, user login</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/token</code></td>
                  <td className="p-3">POST</td>
                  <td className="p-3 text-muted-foreground">Exchange code/credentials for tokens</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/userinfo</code></td>
                  <td className="p-3">GET/POST</td>
                  <td className="p-3 text-muted-foreground">Get user profile with access token</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/introspect</code></td>
                  <td className="p-3">POST</td>
                  <td className="p-3 text-muted-foreground">Check if a token is valid</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/revoke</code></td>
                  <td className="p-3">POST</td>
                  <td className="p-3 text-muted-foreground">Revoke a token</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/end_session</code></td>
                  <td className="p-3">GET</td>
                  <td className="p-3 text-muted-foreground">Logout and end session</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/device_authorization</code></td>
                  <td className="p-3">POST</td>
                  <td className="p-3 text-muted-foreground">Start device code flow</td>
                </tr>
                <tr className="border-t">
                  <td className="p-3"><code className="bg-muted px-1 rounded">/register</code></td>
                  <td className="p-3">POST</td>
                  <td className="p-3 text-muted-foreground">Dynamic client registration</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      <Section title="Discovery Endpoints">
        <div className="border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted">
              <tr>
                <th className="text-left p-3 font-medium">Endpoint</th>
                <th className="text-left p-3 font-medium">Purpose</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-t">
                <td className="p-3"><code className="bg-muted px-1 rounded">/.well-known/openid-configuration</code></td>
                <td className="p-3 text-muted-foreground">OIDC discovery document</td>
              </tr>
              <tr className="border-t">
                <td className="p-3"><code className="bg-muted px-1 rounded">/.well-known/jwks.json</code></td>
                <td className="p-3 text-muted-foreground">Public keys for token verification</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}

function ExamplesTab() {
  return (
    <div className="space-y-6">
      <Section title="Complete Authorization Code Flow with PKCE">
        <p className="text-muted-foreground mb-4">
          This example shows a complete flow for a web application using the authorization code
          grant with PKCE.
        </p>

        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="step1">
            <AccordionTrigger>Step 1: Generate PKCE Values</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Generate a code verifier (random string) and code challenge (SHA256 hash of verifier).
              </p>
              <CodeBlock>{`// JavaScript example
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store codeVerifier securely for step 3`}</CodeBlock>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="step2">
            <AccordionTrigger>Step 2: Redirect to Authorization</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Redirect the user to the authorization endpoint.
              </p>
              <CodeBlock>{`const authUrl = new URL('http://localhost:3000/dev/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
authUrl.searchParams.set('scope', 'openid profile email offline_access');
authUrl.searchParams.set('state', generateRandomState());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();`}</CodeBlock>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="step3">
            <AccordionTrigger>Step 3: Handle Callback</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                After user authenticates, they are redirected back with an authorization code.
              </p>
              <CodeBlock>{`// Callback URL: http://localhost:3001/callback?code=AUTH_CODE&state=xyz

const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// Verify state matches what you sent
if (state !== storedState) {
  throw new Error('State mismatch - possible CSRF attack');
}`}</CodeBlock>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="step4">
            <AccordionTrigger>Step 4: Exchange Code for Tokens</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Exchange the authorization code for tokens. This should be done server-side.
              </p>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=AUTH_CODE" \\
  -d "redirect_uri=http://localhost:3001/callback" \\
  -d "client_id=YOUR_CLIENT_ID" \\
  -d "client_secret=YOUR_CLIENT_SECRET" \\
  -d "code_verifier=ORIGINAL_CODE_VERIFIER"`}</CodeBlock>
              <div className="space-y-2 mt-3">
                <h4 className="font-medium text-sm">Response:</h4>
                <CodeBlock>{`{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email offline_access"
}`}</CodeBlock>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="step5">
            <AccordionTrigger>Step 5: Use the Tokens</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Use the access token to call APIs and the ID token to get user info.
              </p>
              <CodeBlock>{`# Call your API
curl -X GET http://api.example.com/user \\
  -H "Authorization: Bearer ACCESS_TOKEN"

# Or use the userinfo endpoint
curl -X GET http://localhost:3000/dev/userinfo \\
  -H "Authorization: Bearer ACCESS_TOKEN"`}</CodeBlock>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Section>

      <Separator />

      <Section title="Quick Examples">
        <div className="grid gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Get User Info</CardTitle>
            </CardHeader>
            <CardContent>
              <CodeBlock>{`curl http://localhost:3000/dev/userinfo \\
  -H "Authorization: Bearer ACCESS_TOKEN"`}</CodeBlock>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Refresh an Access Token</CardTitle>
            </CardHeader>
            <CardContent>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/token \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -d "grant_type=refresh_token" \\
  -d "refresh_token=REFRESH_TOKEN"`}</CodeBlock>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Revoke a Token</CardTitle>
            </CardHeader>
            <CardContent>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/revoke \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -d "token=TOKEN_TO_REVOKE" \\
  -d "token_type_hint=refresh_token"`}</CodeBlock>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Check Token Validity</CardTitle>
            </CardHeader>
            <CardContent>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/introspect \\
  -u "CLIENT_ID:CLIENT_SECRET" \\
  -d "token=ACCESS_TOKEN"`}</CodeBlock>
            </CardContent>
          </Card>
        </div>
      </Section>
    </div>
  );
}

function TroubleshootingTab() {
  return (
    <div className="space-y-6">
      <Section title="Common Errors">
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="invalid_client">
            <AccordionTrigger>
              <code className="text-destructive">invalid_client</code>
            </AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The client authentication failed.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Common causes:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Wrong client_id or client_secret</li>
                  <li>Using wrong authentication method (basic vs post)</li>
                  <li>Client doesn't exist or is disabled</li>
                </ul>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Solutions:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Verify client credentials in the admin panel</li>
                  <li>Check the client's configured auth method</li>
                  <li>For <code className="bg-muted px-1 rounded">client_secret_basic</code>, use the <code className="bg-muted px-1 rounded">-u</code> flag in curl</li>
                  <li>For <code className="bg-muted px-1 rounded">client_secret_post</code>, include credentials in the body</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="invalid_grant">
            <AccordionTrigger>
              <code className="text-destructive">invalid_grant</code>
            </AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The authorization code or refresh token is invalid or expired.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Common causes:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Authorization code was already used (codes are one-time use)</li>
                  <li>Code or token has expired</li>
                  <li>Refresh token was revoked</li>
                  <li>PKCE code_verifier doesn't match code_challenge</li>
                </ul>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Solutions:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Request a new authorization code</li>
                  <li>Verify PKCE values are correct</li>
                  <li>Check token expiration times</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="invalid_scope">
            <AccordionTrigger>
              <code className="text-destructive">invalid_scope</code>
            </AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The requested scope is invalid or not allowed.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Solutions:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Check that scopes are enabled for the tenant</li>
                  <li>Verify the client has the requested scopes in allowedScopes</li>
                  <li>Ensure scope names are spelled correctly</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="unauthorized_client">
            <AccordionTrigger>
              <code className="text-destructive">unauthorized_client</code>
            </AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The client is not authorized to use the requested grant type.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Solutions:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Add the grant type to the client's allowedGrants</li>
                  <li>Public clients cannot use client_credentials grant</li>
                  <li>Check that the grant type is enabled for the tenant</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="invalid_redirect_uri">
            <AccordionTrigger>
              <code className="text-destructive">invalid_redirect_uri</code>
            </AccordionTrigger>
            <AccordionContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The redirect_uri doesn't match any registered URIs.
              </p>
              <div className="space-y-2">
                <h4 className="font-medium text-sm">Solutions:</h4>
                <ul className="text-sm text-muted-foreground list-disc list-inside space-y-1">
                  <li>Add the exact redirect URI to the client's redirectUris</li>
                  <li>URIs must match exactly (including trailing slashes)</li>
                  <li>Check for http vs https mismatch</li>
                </ul>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Section>

      <Separator />

      <Section title="Debugging Tips">
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Decode JWT Tokens</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Use jwt.io or the command line to inspect token contents:
              </p>
              <CodeBlock>{`# Decode JWT payload (middle part)
echo "TOKEN" | cut -d'.' -f2 | base64 -d | jq`}</CodeBlock>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Check Discovery Document</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Verify the server configuration:
              </p>
              <CodeBlock>{`curl http://localhost:3000/dev/.well-known/openid-configuration | jq`}</CodeBlock>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Verify Token with Introspection</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Check if a token is valid and see its claims:
              </p>
              <CodeBlock>{`curl -X POST http://localhost:3000/dev/introspect \\
  -u "CLIENT_ID:SECRET" \\
  -d "token=YOUR_TOKEN" | jq`}</CodeBlock>
            </CardContent>
          </Card>
        </div>
      </Section>
    </div>
  );
}

export function Help() {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <BookOpen className="h-8 w-8" />
          OAuth 2.0 & OpenID Connect Guide
        </h1>
        <p className="text-muted-foreground mt-1">
          Everything you need to know to integrate with this authorization server
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="grants">Grant Types</TabsTrigger>
          <TabsTrigger value="tokens">Tokens</TabsTrigger>
          <TabsTrigger value="scopes">Scopes</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="examples">Examples</TabsTrigger>
          <TabsTrigger value="troubleshooting">Troubleshooting</TabsTrigger>
        </TabsList>

        <Card className="mt-4">
          <CardContent className="pt-6">
            <ScrollArea className="h-[calc(100vh-280px)]">
              <TabsContent value="overview" className="mt-0">
                <OverviewTab />
              </TabsContent>
              <TabsContent value="grants" className="mt-0">
                <GrantTypesTab />
              </TabsContent>
              <TabsContent value="tokens" className="mt-0">
                <TokensTab />
              </TabsContent>
              <TabsContent value="scopes" className="mt-0">
                <ScopesTab />
              </TabsContent>
              <TabsContent value="endpoints" className="mt-0">
                <EndpointsTab />
              </TabsContent>
              <TabsContent value="examples" className="mt-0">
                <ExamplesTab />
              </TabsContent>
              <TabsContent value="troubleshooting" className="mt-0">
                <TroubleshootingTab />
              </TabsContent>
            </ScrollArea>
          </CardContent>
        </Card>
      </Tabs>
    </div>
  );
}
