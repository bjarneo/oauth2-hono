/**
 * OAuth 2.0 Error Codes
 * RFC 6749 Section 4.1.2.1, 5.2
 * RFC 8628 Section 3.5
 */

// Authorization endpoint errors (RFC 6749 Section 4.1.2.1)
export const ERROR_INVALID_REQUEST = 'invalid_request' as const;
export const ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client' as const;
export const ERROR_ACCESS_DENIED = 'access_denied' as const;
export const ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type' as const;
export const ERROR_INVALID_SCOPE = 'invalid_scope' as const;
export const ERROR_SERVER_ERROR = 'server_error' as const;
export const ERROR_TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable' as const;

// Token endpoint errors (RFC 6749 Section 5.2)
export const ERROR_INVALID_CLIENT = 'invalid_client' as const;
export const ERROR_INVALID_GRANT = 'invalid_grant' as const;
export const ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type' as const;

// Device authorization errors (RFC 8628 Section 3.5)
export const ERROR_AUTHORIZATION_PENDING = 'authorization_pending' as const;
export const ERROR_SLOW_DOWN = 'slow_down' as const;
export const ERROR_EXPIRED_TOKEN = 'expired_token' as const;

// Additional errors
export const ERROR_INVALID_TOKEN = 'invalid_token' as const;
export const ERROR_INSUFFICIENT_SCOPE = 'insufficient_scope' as const;

/**
 * All OAuth error codes
 */
export type OAuthErrorCode =
  | typeof ERROR_INVALID_REQUEST
  | typeof ERROR_UNAUTHORIZED_CLIENT
  | typeof ERROR_ACCESS_DENIED
  | typeof ERROR_UNSUPPORTED_RESPONSE_TYPE
  | typeof ERROR_INVALID_SCOPE
  | typeof ERROR_SERVER_ERROR
  | typeof ERROR_TEMPORARILY_UNAVAILABLE
  | typeof ERROR_INVALID_CLIENT
  | typeof ERROR_INVALID_GRANT
  | typeof ERROR_UNSUPPORTED_GRANT_TYPE
  | typeof ERROR_AUTHORIZATION_PENDING
  | typeof ERROR_SLOW_DOWN
  | typeof ERROR_EXPIRED_TOKEN
  | typeof ERROR_INVALID_TOKEN
  | typeof ERROR_INSUFFICIENT_SCOPE;

/**
 * HTTP status codes for OAuth errors
 */
export const ERROR_STATUS_CODES: Record<OAuthErrorCode, number> = {
  [ERROR_INVALID_REQUEST]: 400,
  [ERROR_UNAUTHORIZED_CLIENT]: 401,
  [ERROR_ACCESS_DENIED]: 403,
  [ERROR_UNSUPPORTED_RESPONSE_TYPE]: 400,
  [ERROR_INVALID_SCOPE]: 400,
  [ERROR_SERVER_ERROR]: 500,
  [ERROR_TEMPORARILY_UNAVAILABLE]: 503,
  [ERROR_INVALID_CLIENT]: 401,
  [ERROR_INVALID_GRANT]: 400,
  [ERROR_UNSUPPORTED_GRANT_TYPE]: 400,
  [ERROR_AUTHORIZATION_PENDING]: 400,
  [ERROR_SLOW_DOWN]: 400,
  [ERROR_EXPIRED_TOKEN]: 400,
  [ERROR_INVALID_TOKEN]: 401,
  [ERROR_INSUFFICIENT_SCOPE]: 403,
};

/**
 * Default error descriptions
 */
export const ERROR_DESCRIPTIONS: Record<OAuthErrorCode, string> = {
  [ERROR_INVALID_REQUEST]:
    'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
  [ERROR_UNAUTHORIZED_CLIENT]:
    'The client is not authorized to request an authorization code using this method.',
  [ERROR_ACCESS_DENIED]: 'The resource owner or authorization server denied the request.',
  [ERROR_UNSUPPORTED_RESPONSE_TYPE]:
    'The authorization server does not support obtaining an authorization code using this method.',
  [ERROR_INVALID_SCOPE]: 'The requested scope is invalid, unknown, or malformed.',
  [ERROR_SERVER_ERROR]:
    'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
  [ERROR_TEMPORARILY_UNAVAILABLE]:
    'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance.',
  [ERROR_INVALID_CLIENT]: 'Client authentication failed.',
  [ERROR_INVALID_GRANT]:
    'The provided authorization grant or refresh token is invalid, expired, revoked, or was issued to another client.',
  [ERROR_UNSUPPORTED_GRANT_TYPE]:
    'The authorization grant type is not supported by the authorization server.',
  [ERROR_AUTHORIZATION_PENDING]:
    'The authorization request is still pending as the end user has not yet completed the user-interaction steps.',
  [ERROR_SLOW_DOWN]: 'The client is polling too frequently.',
  [ERROR_EXPIRED_TOKEN]: 'The device code has expired.',
  [ERROR_INVALID_TOKEN]: 'The access token provided is expired, revoked, malformed, or invalid.',
  [ERROR_INSUFFICIENT_SCOPE]: 'The request requires higher privileges than provided by the access token.',
};
