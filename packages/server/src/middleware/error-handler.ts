import type { ErrorHandler } from 'hono';
import type { OAuthVariables } from '../types/hono.js';
import { OAuthError } from '../errors/oauth-error.js';
import { TOKEN_CACHE_CONTROL, TOKEN_PRAGMA, HEADER_CACHE_CONTROL, HEADER_PRAGMA } from '../config/constants.js';

/**
 * Global error handler for OAuth errors
 *
 * Transforms errors into RFC-compliant OAuth error responses
 */
export const oauthErrorHandler: ErrorHandler<{ Variables: OAuthVariables }> = (
  err,
  c
) => {
  console.error('OAuth Error:', err);

  // Set no-cache headers for error responses
  c.header(HEADER_CACHE_CONTROL, TOKEN_CACHE_CONTROL);
  c.header(HEADER_PRAGMA, TOKEN_PRAGMA);

  if (err instanceof OAuthError) {
    return c.json(err.toJSON(), err.statusCode as 400 | 401 | 403 | 500 | 503);
  }

  // Handle Zod validation errors
  if (err.name === 'ZodError') {
    const zodError = err as { errors?: { message: string }[] };
    const messages = zodError.errors?.map((e) => e.message).join(', ') ?? 'Validation failed';

    return c.json(
      {
        error: 'invalid_request',
        error_description: messages,
      },
      400
    );
  }

  // Handle unexpected errors
  const serverError = OAuthError.serverError(
    process.env['NODE_ENV'] === 'production'
      ? 'An unexpected error occurred'
      : err.message
  );

  return c.json(serverError.toJSON(), 500);
};

/**
 * Security headers middleware
 */
export function securityHeaders() {
  return async (c: Parameters<ErrorHandler<{ Variables: OAuthVariables }>>[1], next: () => Promise<void>) => {
    await next();

    // Prevent clickjacking
    c.header('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    c.header('X-Content-Type-Options', 'nosniff');

    // Enable XSS protection
    c.header('X-XSS-Protection', '1; mode=block');

    // Referrer policy
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Content Security Policy for authorization pages
    if (c.req.path.includes('/authorize')) {
      c.header(
        'Content-Security-Policy',
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
      );
    }

    // Strict Transport Security (enable in production with HTTPS)
    if (process.env['NODE_ENV'] === 'production') {
      c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
  };
}

/**
 * Request logging middleware
 */
export function requestLogger() {
  return async (c: Parameters<ErrorHandler<{ Variables: OAuthVariables }>>[1], next: () => Promise<void>) => {
    const start = Date.now();
    const method = c.req.method;
    const path = c.req.path;

    await next();

    const duration = Date.now() - start;
    const status = c.res.status;

    // Don't log sensitive data
    console.log(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        method,
        path,
        status,
        duration,
        tenant: (c.get('tenant' as never) as { slug?: string } | undefined)?.slug,
      })
    );
  };
}
