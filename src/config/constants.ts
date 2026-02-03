/**
 * OAuth 2.0 Constants
 */

// Grant type URIs
export const GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code' as const;
export const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials' as const;
export const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token' as const;
export const GRANT_TYPE_DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code' as const;

// All supported grant types
export const SUPPORTED_GRANT_TYPES = [
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  GRANT_TYPE_DEVICE_CODE,
] as const;

// Response types
export const RESPONSE_TYPE_CODE = 'code' as const;
export const SUPPORTED_RESPONSE_TYPES = [RESPONSE_TYPE_CODE] as const;

// Code challenge methods (RFC 9700: S256 only)
export const CODE_CHALLENGE_METHOD_S256 = 'S256' as const;
export const SUPPORTED_CODE_CHALLENGE_METHODS = [CODE_CHALLENGE_METHOD_S256] as const;

// Token types
export const TOKEN_TYPE_BEARER = 'Bearer' as const;

// Client authentication methods
export const CLIENT_AUTH_BASIC = 'client_secret_basic' as const;
export const CLIENT_AUTH_POST = 'client_secret_post' as const;
export const CLIENT_AUTH_PRIVATE_KEY_JWT = 'private_key_jwt' as const;
export const CLIENT_AUTH_NONE = 'none' as const;

export const SUPPORTED_CLIENT_AUTH_METHODS = [
  CLIENT_AUTH_BASIC,
  CLIENT_AUTH_POST,
  CLIENT_AUTH_PRIVATE_KEY_JWT,
  CLIENT_AUTH_NONE,
] as const;

// Signing algorithms
export const SIGNING_ALGORITHM_RS256 = 'RS256' as const;
export const SIGNING_ALGORITHM_RS384 = 'RS384' as const;
export const SIGNING_ALGORITHM_RS512 = 'RS512' as const;
export const SIGNING_ALGORITHM_ES256 = 'ES256' as const;
export const SIGNING_ALGORITHM_ES384 = 'ES384' as const;
export const SIGNING_ALGORITHM_ES512 = 'ES512' as const;

export const SUPPORTED_SIGNING_ALGORITHMS = [
  SIGNING_ALGORITHM_RS256,
  SIGNING_ALGORITHM_RS384,
  SIGNING_ALGORITHM_RS512,
  SIGNING_ALGORITHM_ES256,
  SIGNING_ALGORITHM_ES384,
  SIGNING_ALGORITHM_ES512,
] as const;

// Default TTLs (in seconds)
export const DEFAULT_ACCESS_TOKEN_TTL = 3600; // 1 hour
export const DEFAULT_REFRESH_TOKEN_TTL = 2592000; // 30 days
export const DEFAULT_AUTHORIZATION_CODE_TTL = 600; // 10 minutes
export const DEFAULT_DEVICE_CODE_TTL = 1800; // 30 minutes
export const DEFAULT_DEVICE_CODE_INTERVAL = 5; // 5 seconds

// Token/code lengths
export const AUTHORIZATION_CODE_LENGTH = 32; // bytes
export const REFRESH_TOKEN_LENGTH = 32; // bytes
export const DEVICE_CODE_LENGTH = 32; // bytes
export const USER_CODE_LENGTH = 8; // characters (e.g., ABCD-EFGH)
export const CLIENT_ID_LENGTH = 16; // bytes
export const CLIENT_SECRET_LENGTH = 32; // bytes

// User code charset (easy to type, avoid ambiguous chars)
export const USER_CODE_CHARSET = 'BCDFGHJKLMNPQRSTVWXZ'; // No vowels, no 0/O, no 1/I

// Rate limiting defaults
export const DEFAULT_RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
export const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 100;

// OpenID Connect scopes
export const OPENID_SCOPE = 'openid' as const;
export const PROFILE_SCOPE = 'profile' as const;
export const EMAIL_SCOPE = 'email' as const;
export const OFFLINE_ACCESS_SCOPE = 'offline_access' as const;

export const STANDARD_SCOPES = [
  OPENID_SCOPE,
  PROFILE_SCOPE,
  EMAIL_SCOPE,
  OFFLINE_ACCESS_SCOPE,
] as const;

// HTTP headers
export const HEADER_AUTHORIZATION = 'Authorization';
export const HEADER_CONTENT_TYPE = 'Content-Type';
export const HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate';
export const HEADER_CACHE_CONTROL = 'Cache-Control';
export const HEADER_PRAGMA = 'Pragma';

// Content types
export const CONTENT_TYPE_JSON = 'application/json';
export const CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded';

// Cache control for token responses
export const TOKEN_CACHE_CONTROL = 'no-store';
export const TOKEN_PRAGMA = 'no-cache';
