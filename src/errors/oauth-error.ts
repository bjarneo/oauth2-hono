import {
  type OAuthErrorCode,
  ERROR_STATUS_CODES,
  ERROR_DESCRIPTIONS,
  ERROR_INVALID_REQUEST,
  ERROR_INVALID_CLIENT,
  ERROR_INVALID_GRANT,
  ERROR_UNAUTHORIZED_CLIENT,
  ERROR_ACCESS_DENIED,
  ERROR_UNSUPPORTED_RESPONSE_TYPE,
  ERROR_INVALID_SCOPE,
  ERROR_UNSUPPORTED_GRANT_TYPE,
  ERROR_SERVER_ERROR,
  ERROR_TEMPORARILY_UNAVAILABLE,
  ERROR_AUTHORIZATION_PENDING,
  ERROR_SLOW_DOWN,
  ERROR_EXPIRED_TOKEN,
  ERROR_INVALID_TOKEN,
  ERROR_INSUFFICIENT_SCOPE,
} from './error-codes.js';

/**
 * OAuth 2.0 Error Response
 * RFC 6749 Section 5.2
 */
export interface OAuthErrorResponse {
  error: OAuthErrorCode;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * OAuth 2.0 Error class
 * Represents RFC-compliant OAuth errors
 */
export class OAuthError extends Error {
  public readonly code: OAuthErrorCode;
  public readonly statusCode: number;
  public readonly description: string;
  public readonly errorUri?: string;
  public readonly state?: string;

  constructor(
    code: OAuthErrorCode,
    description?: string,
    options?: {
      errorUri?: string;
      state?: string;
      cause?: Error;
    }
  ) {
    const desc = description ?? ERROR_DESCRIPTIONS[code];
    super(desc);
    this.name = 'OAuthError';
    this.code = code;
    this.statusCode = ERROR_STATUS_CODES[code];
    this.description = desc;

    if (options?.errorUri) {
      this.errorUri = options.errorUri;
    }
    if (options?.state) {
      this.state = options.state;
    }
    if (options?.cause) {
      this.cause = options.cause;
    }

    // Maintains proper stack trace in V8
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Convert to JSON response body
   */
  toJSON(): OAuthErrorResponse {
    const response: OAuthErrorResponse = {
      error: this.code,
    };

    if (this.description) {
      response.error_description = this.description;
    }

    if (this.errorUri) {
      response.error_uri = this.errorUri;
    }

    if (this.state) {
      response.state = this.state;
    }

    return response;
  }

  /**
   * Convert to URL query string for redirect errors
   */
  toQueryString(): string {
    const params = new URLSearchParams();
    params.set('error', this.code);

    if (this.description) {
      params.set('error_description', this.description);
    }

    if (this.errorUri) {
      params.set('error_uri', this.errorUri);
    }

    if (this.state) {
      params.set('state', this.state);
    }

    return params.toString();
  }

  // Factory methods for common errors

  static invalidRequest(description?: string, state?: string): OAuthError {
    return new OAuthError(ERROR_INVALID_REQUEST, description, { state });
  }

  static invalidClient(description?: string): OAuthError {
    return new OAuthError(ERROR_INVALID_CLIENT, description);
  }

  static invalidGrant(description?: string): OAuthError {
    return new OAuthError(ERROR_INVALID_GRANT, description);
  }

  static unauthorizedClient(description?: string, state?: string): OAuthError {
    return new OAuthError(ERROR_UNAUTHORIZED_CLIENT, description, { state });
  }

  static accessDenied(description?: string, state?: string): OAuthError {
    return new OAuthError(ERROR_ACCESS_DENIED, description, { state });
  }

  static unsupportedResponseType(description?: string, state?: string): OAuthError {
    return new OAuthError(ERROR_UNSUPPORTED_RESPONSE_TYPE, description, { state });
  }

  static invalidScope(description?: string, state?: string): OAuthError {
    return new OAuthError(ERROR_INVALID_SCOPE, description, { state });
  }

  static unsupportedGrantType(description?: string): OAuthError {
    return new OAuthError(ERROR_UNSUPPORTED_GRANT_TYPE, description);
  }

  static serverError(description?: string, cause?: Error): OAuthError {
    return new OAuthError(ERROR_SERVER_ERROR, description, { cause });
  }

  static temporarilyUnavailable(description?: string): OAuthError {
    return new OAuthError(ERROR_TEMPORARILY_UNAVAILABLE, description);
  }

  static authorizationPending(): OAuthError {
    return new OAuthError(ERROR_AUTHORIZATION_PENDING);
  }

  static slowDown(): OAuthError {
    return new OAuthError(ERROR_SLOW_DOWN);
  }

  static expiredToken(): OAuthError {
    return new OAuthError(ERROR_EXPIRED_TOKEN);
  }

  static invalidToken(description?: string): OAuthError {
    return new OAuthError(ERROR_INVALID_TOKEN, description);
  }

  static insufficientScope(description?: string): OAuthError {
    return new OAuthError(ERROR_INSUFFICIENT_SCOPE, description);
  }
}
