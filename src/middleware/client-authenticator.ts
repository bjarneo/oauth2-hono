import type { MiddlewareHandler, Context } from 'hono';
import type { OAuthVariables } from '../types/hono.js';
import type { OAuthClient, AuthenticatedClient, ClientAuthMethod } from '../types/client.js';
import type { IClientStorage } from '../storage/interfaces/index.js';
import { OAuthError } from '../errors/oauth-error.js';
import { verifyClientAssertion } from '../crypto/jwt.js';
import { verifyClientSecret } from '../crypto/hash.js';
import {
  CLIENT_AUTH_BASIC,
  CLIENT_AUTH_POST,
  CLIENT_AUTH_PRIVATE_KEY_JWT,
  CLIENT_AUTH_NONE,
  HEADER_AUTHORIZATION,
} from '../config/constants.js';

export interface ClientAuthenticatorOptions {
  clientStorage: IClientStorage;
  allowPublicClients?: boolean; // Allow clients with auth_method='none'
  tokenEndpointUrl?: string; // Required for private_key_jwt validation
}

/**
 * Extract client credentials from Basic auth header
 */
function extractBasicAuth(authHeader: string): { clientId: string; clientSecret: string } | null {
  if (!authHeader.startsWith('Basic ')) {
    return null;
  }

  const base64 = authHeader.slice(6);
  let decoded: string;

  try {
    decoded = Buffer.from(base64, 'base64').toString('utf-8');
  } catch {
    return null;
  }

  const colonIndex = decoded.indexOf(':');
  if (colonIndex === -1) {
    return null;
  }

  return {
    clientId: decodeURIComponent(decoded.slice(0, colonIndex)),
    clientSecret: decodeURIComponent(decoded.slice(colonIndex + 1)),
  };
}

/**
 * Extract client credentials from POST body
 */
async function extractPostAuth(
  c: Context
): Promise<{ clientId: string; clientSecret?: string; clientAssertion?: string; clientAssertionType?: string } | null> {
  const contentType = c.req.header('content-type');
  if (!contentType?.includes('application/x-www-form-urlencoded')) {
    return null;
  }

  const body = await c.req.parseBody();
  const clientId = body['client_id'];

  if (typeof clientId !== 'string') {
    return null;
  }

  return {
    clientId,
    clientSecret: typeof body['client_secret'] === 'string' ? body['client_secret'] : undefined,
    clientAssertion: typeof body['client_assertion'] === 'string' ? body['client_assertion'] : undefined,
    clientAssertionType: typeof body['client_assertion_type'] === 'string' ? body['client_assertion_type'] : undefined,
  };
}

/**
 * Middleware to authenticate OAuth clients
 *
 * Supports:
 * - client_secret_basic: HTTP Basic authentication
 * - client_secret_post: Credentials in POST body
 * - private_key_jwt: JWT assertion signed with client's private key
 * - none: Public clients (no authentication)
 *
 * Sets `client` in context variables on success
 */
export function clientAuthenticator(options: ClientAuthenticatorOptions): MiddlewareHandler<{
  Variables: OAuthVariables;
}> {
  const { clientStorage, allowPublicClients = true, tokenEndpointUrl } = options;

  return async (c, next) => {
    const tenant = c.get('tenant');
    if (!tenant) {
      throw OAuthError.serverError('Tenant not resolved');
    }

    const authHeader = c.req.header(HEADER_AUTHORIZATION);
    let client: OAuthClient | null = null;
    let authMethod: ClientAuthMethod | null = null;

    // Try Basic authentication first
    if (authHeader) {
      const basicCreds = extractBasicAuth(authHeader);
      if (basicCreds) {
        client = await clientStorage.findByClientId(tenant.id, basicCreds.clientId);

        if (!client) {
          throw OAuthError.invalidClient('Unknown client');
        }

        if (client.authMethod !== CLIENT_AUTH_BASIC) {
          throw OAuthError.invalidClient(
            `Client is not configured for Basic authentication`
          );
        }

        if (!client.clientSecretHash) {
          throw OAuthError.invalidClient('Client has no secret configured');
        }

        const isValid = await verifyClientSecret(basicCreds.clientSecret, client.clientSecretHash);
        if (!isValid) {
          throw OAuthError.invalidClient('Invalid client credentials');
        }

        authMethod = CLIENT_AUTH_BASIC;
      }
    }

    // Try POST body authentication if Basic didn't work
    if (!client) {
      const postCreds = await extractPostAuth(c);

      if (postCreds) {
        client = await clientStorage.findByClientId(tenant.id, postCreds.clientId);

        if (!client) {
          throw OAuthError.invalidClient('Unknown client');
        }

        // Handle private_key_jwt
        if (
          postCreds.clientAssertion &&
          postCreds.clientAssertionType === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        ) {
          if (client.authMethod !== CLIENT_AUTH_PRIVATE_KEY_JWT) {
            throw OAuthError.invalidClient('Client is not configured for JWT authentication');
          }

          if (!client.jwks && !client.jwksUri) {
            throw OAuthError.invalidClient('Client has no JWKS configured');
          }

          if (!tokenEndpointUrl) {
            throw OAuthError.serverError('Token endpoint URL not configured for JWT validation');
          }

          // Get client's public keys
          let jwks: { keys: object[] };
          if (client.jwks) {
            jwks = client.jwks;
          } else if (client.jwksUri) {
            // Fetch JWKS from URI
            const response = await fetch(client.jwksUri);
            if (!response.ok) {
              throw OAuthError.invalidClient('Failed to fetch client JWKS');
            }
            jwks = await response.json() as { keys: object[] };
          } else {
            throw OAuthError.invalidClient('No JWKS available');
          }

          try {
            await verifyClientAssertion(postCreds.clientAssertion, jwks as Parameters<typeof verifyClientAssertion>[1], {
              issuer: client.clientId,
              audience: tokenEndpointUrl,
            });
          } catch (error) {
            throw OAuthError.invalidClient('Invalid client assertion');
          }

          authMethod = CLIENT_AUTH_PRIVATE_KEY_JWT;
        }
        // Handle client_secret_post
        else if (postCreds.clientSecret) {
          if (client.authMethod !== CLIENT_AUTH_POST) {
            throw OAuthError.invalidClient('Client is not configured for POST authentication');
          }

          if (!client.clientSecretHash) {
            throw OAuthError.invalidClient('Client has no secret configured');
          }

          const isValid = await verifyClientSecret(postCreds.clientSecret, client.clientSecretHash);
          if (!isValid) {
            throw OAuthError.invalidClient('Invalid client credentials');
          }

          authMethod = CLIENT_AUTH_POST;
        }
        // Handle public client (none)
        else if (client.authMethod === CLIENT_AUTH_NONE) {
          if (!allowPublicClients) {
            throw OAuthError.invalidClient('Public clients are not allowed');
          }
          authMethod = CLIENT_AUTH_NONE;
        }
        // Client ID provided but no credentials - error unless public client
        else {
          throw OAuthError.invalidClient('Client credentials required');
        }
      }
    }

    if (!client || !authMethod) {
      throw OAuthError.invalidClient('Client authentication required');
    }

    // Set authenticated client in context
    const authenticatedClient: AuthenticatedClient = {
      client,
      authMethod,
    };
    c.set('client', authenticatedClient);

    await next();
  };
}

/**
 * Middleware to optionally authenticate clients (for endpoints that support both
 * authenticated and unauthenticated requests)
 */
export function optionalClientAuthenticator(options: ClientAuthenticatorOptions): MiddlewareHandler<{
  Variables: OAuthVariables;
}> {
  const { clientStorage } = options;

  return async (c, next) => {
    const tenant = c.get('tenant');
    if (!tenant) {
      throw OAuthError.serverError('Tenant not resolved');
    }

    const authHeader = c.req.header(HEADER_AUTHORIZATION);

    // Try Basic authentication
    if (authHeader) {
      const basicCreds = extractBasicAuth(authHeader);
      if (basicCreds) {
        const client = await clientStorage.findByClientId(tenant.id, basicCreds.clientId);

        if (client && client.clientSecretHash) {
          const isValid = await verifyClientSecret(basicCreds.clientSecret, client.clientSecretHash);
          if (isValid) {
            c.set('client', { client, authMethod: CLIENT_AUTH_BASIC });
          }
        }
      }
    }

    // Try POST body if not already authenticated
    if (!c.get('client')) {
      const postCreds = await extractPostAuth(c);
      if (postCreds) {
        const client = await clientStorage.findByClientId(tenant.id, postCreds.clientId);

        if (client) {
          if (postCreds.clientSecret && client.clientSecretHash) {
            const isValid = await verifyClientSecret(postCreds.clientSecret, client.clientSecretHash);
            if (isValid) {
              c.set('client', { client, authMethod: CLIENT_AUTH_POST });
            }
          } else if (client.authMethod === CLIENT_AUTH_NONE) {
            c.set('client', { client, authMethod: CLIENT_AUTH_NONE });
          }
        }
      }
    }

    await next();
  };
}
