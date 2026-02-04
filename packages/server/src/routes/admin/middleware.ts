import type { Context, Next } from 'hono';
import type { OAuthVariables } from '../../types/hono.js';

export interface AdminAuthOptions {
  apiKey?: string;
  headerName?: string;
}

/**
 * Admin API authentication middleware
 * Validates API key from header
 */
export function adminAuth(options: AdminAuthOptions = {}) {
  const { apiKey, headerName = 'x-api-key' } = options;

  return async (c: Context<{ Variables: OAuthVariables }>, next: Next) => {
    // If no API key is configured, allow all requests (development mode)
    if (!apiKey) {
      return next();
    }

    const providedKey = c.req.header(headerName) || c.req.header('Authorization')?.replace('Bearer ', '');

    if (!providedKey) {
      return c.json({ error: 'unauthorized', message: 'API key required' }, 401);
    }

    if (providedKey !== apiKey) {
      return c.json({ error: 'forbidden', message: 'Invalid API key' }, 403);
    }

    return next();
  };
}
