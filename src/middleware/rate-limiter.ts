import type { MiddlewareHandler } from 'hono';
import type { OAuthVariables } from '../types/hono.js';
import { OAuthError } from '../errors/oauth-error.js';

export interface RateLimiterOptions {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  keyGenerator?: (c: Parameters<MiddlewareHandler>[0]) => string; // Custom key generator
  skipFailedRequests?: boolean; // Don't count failed requests
  skipSuccessfulRequests?: boolean; // Don't count successful requests
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Simple in-memory rate limiter
 * For production, use Redis or similar distributed store
 */
export function rateLimiter(options: RateLimiterOptions): MiddlewareHandler<{
  Variables: OAuthVariables;
}> {
  const {
    windowMs,
    maxRequests,
    keyGenerator = defaultKeyGenerator,
    skipFailedRequests = false,
    skipSuccessfulRequests = false,
  } = options;

  const store = new Map<string, RateLimitEntry>();

  // Cleanup expired entries periodically
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (entry.resetAt <= now) {
        store.delete(key);
      }
    }
  }, windowMs);

  // Prevent the interval from keeping the process alive
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }

  return async (c, next) => {
    const key = keyGenerator(c);
    const now = Date.now();

    let entry = store.get(key);

    // Create new entry if doesn't exist or window has passed
    if (!entry || entry.resetAt <= now) {
      entry = {
        count: 0,
        resetAt: now + windowMs,
      };
      store.set(key, entry);
    }

    // Check if over limit
    if (entry.count >= maxRequests) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      c.header('Retry-After', String(retryAfter));
      c.header('X-RateLimit-Limit', String(maxRequests));
      c.header('X-RateLimit-Remaining', '0');
      c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));

      throw OAuthError.temporarilyUnavailable(
        `Rate limit exceeded. Try again in ${retryAfter} seconds.`
      );
    }

    // Set rate limit headers
    c.header('X-RateLimit-Limit', String(maxRequests));
    c.header('X-RateLimit-Remaining', String(maxRequests - entry.count - 1));
    c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));

    // Increment counter before request (unless skipping successful)
    if (!skipSuccessfulRequests) {
      entry.count++;
    }

    try {
      await next();

      // If skipping successful and request succeeded, don't count
      // (already counted above, so decrement)
      if (skipSuccessfulRequests && c.res.status < 400) {
        // Request was successful, count it
        entry.count++;
      }
    } catch (error) {
      // If skipping failed requests, decrement the counter
      if (skipFailedRequests && !skipSuccessfulRequests) {
        entry.count--;
      }
      throw error;
    }
  };
}

/**
 * Default key generator: uses IP address and tenant
 */
function defaultKeyGenerator(c: Parameters<MiddlewareHandler>[0]): string {
  const ip =
    c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ??
    c.req.header('x-real-ip') ??
    'unknown';

  const tenant = c.get('tenant' as never) as { id?: string } | undefined;
  const tenantId = tenant?.id ?? 'global';

  return `${tenantId}:${ip}`;
}

/**
 * Create endpoint-specific rate limiter
 */
export function endpointRateLimiter(
  endpoint: string,
  options: RateLimiterOptions
): MiddlewareHandler<{ Variables: OAuthVariables }> {
  return rateLimiter({
    ...options,
    keyGenerator: (c) => {
      const baseKey = defaultKeyGenerator(c);
      return `${endpoint}:${baseKey}`;
    },
  });
}

/**
 * Token endpoint rate limiter (stricter limits)
 */
export function tokenEndpointRateLimiter(
  windowMs: number = 60000,
  maxRequests: number = 30
): MiddlewareHandler<{ Variables: OAuthVariables }> {
  return endpointRateLimiter('token', { windowMs, maxRequests });
}

/**
 * Authorization endpoint rate limiter
 */
export function authorizationEndpointRateLimiter(
  windowMs: number = 60000,
  maxRequests: number = 60
): MiddlewareHandler<{ Variables: OAuthVariables }> {
  return endpointRateLimiter('authorize', { windowMs, maxRequests });
}

/**
 * Device code polling rate limiter (enforces interval)
 */
export function deviceCodeRateLimiter(
  interval: number = 5000
): MiddlewareHandler<{ Variables: OAuthVariables }> {
  return rateLimiter({
    windowMs: interval,
    maxRequests: 1,
    keyGenerator: (c) => {
      const ip =
        c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ??
        c.req.header('x-real-ip') ??
        'unknown';
      // Rate limit per device code request (by IP)
      return `device:${ip}`;
    },
  });
}
