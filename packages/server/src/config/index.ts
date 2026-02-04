import { readFileSync, existsSync } from 'node:fs';
import * as constants from './constants.js';

/**
 * Read a secret from file (Docker secrets) or environment variable
 * Supports both `VAR_FILE` (path to file) and `VAR` (direct value) patterns
 */
function readSecret(envVar: string): string | undefined {
  // Check for file-based secret first (Docker secrets pattern)
  const fileEnvVar = `${envVar}_FILE`;
  const filePath = process.env[fileEnvVar];

  if (filePath && existsSync(filePath)) {
    try {
      return readFileSync(filePath, 'utf-8').trim();
    } catch {
      console.warn(`Warning: Could not read secret from ${filePath}`);
    }
  }

  // Fall back to direct environment variable
  return process.env[envVar];
}

/**
 * Application configuration loaded from environment
 */
export interface Config {
  server: {
    port: number;
    host: string;
    nodeEnv: string;
  };
  database: {
    url: string | undefined;
  };
  secrets: {
    adminApiKey: string | undefined;
    encryptionKey: string | undefined;
    jwtSigningKey: string | undefined;
  };
  logging: {
    level: string;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
  defaults: {
    accessTokenTtl: number;
    refreshTokenTtl: number;
    authorizationCodeTtl: number;
    deviceCodeTtl: number;
    deviceCodeInterval: number;
  };
}

/**
 * Load configuration from environment variables
 */
export function loadConfig(): Config {
  return {
    server: {
      port: parseInt(process.env['PORT'] ?? '3000', 10),
      host: process.env['HOST'] ?? '0.0.0.0',
      nodeEnv: process.env['NODE_ENV'] ?? 'development',
    },
    database: {
      url: process.env['DATABASE_URL'],
    },
    secrets: {
      adminApiKey: readSecret('ADMIN_API_KEY'),
      encryptionKey: readSecret('ENCRYPTION_KEY'),
      jwtSigningKey: readSecret('JWT_SIGNING_KEY'),
    },
    logging: {
      level: process.env['LOG_LEVEL'] ?? 'info',
    },
    rateLimit: {
      windowMs: parseInt(
        process.env['RATE_LIMIT_WINDOW_MS'] ?? String(constants.DEFAULT_RATE_LIMIT_WINDOW_MS),
        10
      ),
      maxRequests: parseInt(
        process.env['RATE_LIMIT_MAX_REQUESTS'] ?? String(constants.DEFAULT_RATE_LIMIT_MAX_REQUESTS),
        10
      ),
    },
    defaults: {
      accessTokenTtl: parseInt(
        process.env['DEFAULT_ACCESS_TOKEN_TTL'] ?? String(constants.DEFAULT_ACCESS_TOKEN_TTL),
        10
      ),
      refreshTokenTtl: parseInt(
        process.env['DEFAULT_REFRESH_TOKEN_TTL'] ?? String(constants.DEFAULT_REFRESH_TOKEN_TTL),
        10
      ),
      authorizationCodeTtl: parseInt(
        process.env['DEFAULT_AUTHORIZATION_CODE_TTL'] ?? String(constants.DEFAULT_AUTHORIZATION_CODE_TTL),
        10
      ),
      deviceCodeTtl: parseInt(
        process.env['DEFAULT_DEVICE_CODE_TTL'] ?? String(constants.DEFAULT_DEVICE_CODE_TTL),
        10
      ),
      deviceCodeInterval: parseInt(
        process.env['DEFAULT_DEVICE_CODE_INTERVAL'] ?? String(constants.DEFAULT_DEVICE_CODE_INTERVAL),
        10
      ),
    },
  };
}

// Singleton config instance
let config: Config | null = null;

/**
 * Get the current configuration (loads if not already loaded)
 */
export function getConfig(): Config {
  if (!config) {
    config = loadConfig();
  }
  return config;
}

/**
 * Reset configuration (useful for testing)
 */
export function resetConfig(): void {
  config = null;
}

// Re-export constants
export { constants };
