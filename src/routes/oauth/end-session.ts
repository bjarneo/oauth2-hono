import { Hono } from 'hono';
import * as jose from 'jose';
import type { OAuthVariables } from '../../types/hono.js';
import type { IStorage } from '../../storage/interfaces/index.js';
import type { IUserAuthenticator } from '../../storage/interfaces/user-storage.js';
import type { LogoutTokenPayload } from '../../types/token.js';
import { OAuthError } from '../../errors/oauth-error.js';
import { signLogoutToken } from '../../crypto/jwt.js';

export interface EndSessionRoutesOptions {
  storage: IStorage;
  userAuthenticator?: IUserAuthenticator;
  /**
   * Callback to invalidate user session
   * This is called when a logout is requested
   */
  onLogout?: (tenantId: string, userId: string, clientId?: string) => Promise<void>;
}

/**
 * Create End Session (Logout) endpoint
 *
 * GET/POST /:tenant/end_session
 *
 * Handles RP-initiated logout per OpenID Connect RP-Initiated Logout 1.0
 *
 * Parameters:
 * - id_token_hint: Previously issued ID token (recommended)
 * - post_logout_redirect_uri: URL to redirect after logout
 * - state: Opaque value for client
 * - client_id: Client identifier (required if id_token_hint not provided)
 */
export function createEndSessionRoutes(options: EndSessionRoutesOptions) {
  const { storage, userAuthenticator, onLogout } = options;

  const router = new Hono<{ Variables: OAuthVariables }>();

  const handleEndSession = async (c: any) => {
    const tenant = c.get('tenant');

    // Extract parameters from query (GET) or body (POST)
    const params = c.req.method === 'GET'
      ? Object.fromEntries(new URL(c.req.url).searchParams)
      : await c.req.parseBody();

    const idTokenHint = params['id_token_hint'] as string | undefined;
    const postLogoutRedirectUri = params['post_logout_redirect_uri'] as string | undefined;
    const state = params['state'] as string | undefined;
    let clientId = params['client_id'] as string | undefined;

    let userId: string | undefined;
    let sessionId: string | undefined;

    // Validate id_token_hint if provided
    if (idTokenHint) {
      try {
        // Decode without verification first to get the claims
        const decoded = jose.decodeJwt(idTokenHint);

        // Verify the token was issued by this tenant
        if (decoded.iss !== tenant.issuer) {
          throw OAuthError.invalidRequest('ID token was not issued by this authorization server');
        }

        userId = decoded.sub as string;
        clientId = clientId || (decoded.aud as string);
        sessionId = decoded.sid as string | undefined;

        // Get signing keys to verify the token
        const signingKeys = await storage.signingKeys.listByTenant(tenant.id);

        let verified = false;
        for (const signingKey of signingKeys) {
          try {
            const publicKey = await jose.importSPKI(
              signingKey.publicKey,
              signingKey.algorithm
            );

            // Verify signature (but allow expired tokens for logout)
            await jose.jwtVerify(idTokenHint, publicKey, {
              issuer: tenant.issuer,
              clockTolerance: Number.MAX_SAFE_INTEGER, // Accept expired tokens
            });
            verified = true;
            break;
          } catch {
            // Try next key
          }
        }

        if (!verified) {
          throw OAuthError.invalidRequest('Invalid ID token signature');
        }
      } catch (error) {
        if (error instanceof OAuthError) {
          throw error;
        }
        throw OAuthError.invalidRequest('Invalid id_token_hint');
      }
    }

    // Validate post_logout_redirect_uri
    if (postLogoutRedirectUri) {
      if (!clientId) {
        throw OAuthError.invalidRequest(
          'client_id is required when post_logout_redirect_uri is provided'
        );
      }

      const client = await storage.clients.findByClientId(tenant.id, clientId);
      if (!client) {
        throw OAuthError.invalidRequest('Unknown client_id');
      }

      // Check if the URI is registered
      const allowedUris = client.postLogoutRedirectUris || [];
      if (!allowedUris.includes(postLogoutRedirectUri)) {
        throw OAuthError.invalidRequest('Invalid post_logout_redirect_uri');
      }
    }

    // Perform logout actions
    if (userId) {
      // Revoke all refresh tokens for the user (or just for the client if specified)
      if (clientId) {
        await storage.refreshTokens.revokeByUserAndClient(tenant.id, userId, clientId);
      } else {
        await storage.refreshTokens.revokeByUser(tenant.id, userId);
      }

      // Call the custom logout callback
      if (onLogout) {
        await onLogout(tenant.id, userId, clientId);
      }

      // Revoke consent if userAuthenticator supports it
      if (userAuthenticator && clientId) {
        try {
          await userAuthenticator.revokeConsent(tenant.id, userId, clientId);
        } catch {
          // Ignore errors in consent revocation
        }
      }

      // Trigger back-channel logout for all registered clients
      await triggerBackChannelLogout(tenant, userId, sessionId, storage);
    }

    // Redirect or return success
    if (postLogoutRedirectUri) {
      const url = new URL(postLogoutRedirectUri);
      if (state) {
        url.searchParams.set('state', state);
      }
      return c.redirect(url.toString());
    }

    // Return a simple logout confirmation page
    return c.html(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Logged Out</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 2rem;
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h1 { color: #333; }
    p { color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Logged Out</h1>
    <p>You have been successfully logged out.</p>
  </div>
</body>
</html>
    `);
  };

  router.get('/', handleEndSession);
  router.post('/', handleEndSession);

  return router;
}

/**
 * Trigger back-channel logout for all clients that support it
 */
async function triggerBackChannelLogout(
  tenant: any,
  userId: string,
  sessionId: string | undefined,
  storage: IStorage
): Promise<void> {
  // Get all clients for the tenant
  const clients = await storage.clients.listByTenant(tenant.id);

  // Get primary signing key
  const signingKey = await storage.signingKeys.getPrimary(tenant.id);
  if (!signingKey) {
    return;
  }

  for (const client of clients) {
    if (!client.backchannelLogoutUri) {
      continue;
    }

    try {
      // Create logout token
      const logoutTokenPayload: Omit<LogoutTokenPayload, 'jti'> = {
        iss: tenant.issuer,
        sub: userId,
        aud: client.clientId,
        iat: Math.floor(Date.now() / 1000),
        events: {
          'http://schemas.openid.net/event/backchannel-logout': {},
        },
      };

      if (sessionId && client.backchannelLogoutSessionRequired) {
        (logoutTokenPayload as any).sid = sessionId;
      }

      const logoutToken = await signLogoutToken(logoutTokenPayload, signingKey);

      // Send logout token to client's back-channel logout URI
      await fetch(client.backchannelLogoutUri, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          logout_token: logoutToken,
        }),
        signal: AbortSignal.timeout(10000), // 10 second timeout
      });
    } catch {
      // Log error but don't fail the logout
      console.error(`Failed to send back-channel logout to client ${client.clientId}`);
    }
  }
}
