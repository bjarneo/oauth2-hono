import { randomBytes } from 'node:crypto';
import { USER_CODE_CHARSET, USER_CODE_LENGTH } from '../config/constants.js';

/**
 * Generate cryptographically secure random bytes as hex string
 */
export function generateRandomHex(length: number): string {
  return randomBytes(length).toString('hex');
}

/**
 * Generate cryptographically secure random bytes as base64url string
 */
export function generateRandomBase64Url(length: number): string {
  return randomBytes(length)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a secure random client ID
 */
export function generateClientId(length: number = 16): string {
  return generateRandomBase64Url(length);
}

/**
 * Generate a secure random client secret
 */
export function generateClientSecret(length: number = 32): string {
  return generateRandomBase64Url(length);
}

/**
 * Generate a secure authorization code
 */
export function generateAuthorizationCode(length: number = 32): string {
  return generateRandomBase64Url(length);
}

/**
 * Generate a secure refresh token
 */
export function generateRefreshToken(length: number = 32): string {
  return generateRandomBase64Url(length);
}

/**
 * Generate a secure device code
 */
export function generateDeviceCode(length: number = 32): string {
  return generateRandomBase64Url(length);
}

/**
 * Generate a user-friendly user code for device authorization
 * Format: XXXX-XXXX (easy to type, no ambiguous characters)
 */
export function generateUserCode(length: number = USER_CODE_LENGTH): string {
  const bytes = randomBytes(length);
  let code = '';

  for (let i = 0; i < length; i++) {
    const index = bytes[i]! % USER_CODE_CHARSET.length;
    code += USER_CODE_CHARSET[index];
    // Add hyphen in the middle
    if (i === length / 2 - 1) {
      code += '-';
    }
  }

  return code;
}

/**
 * Generate a unique JWT ID (jti)
 */
export function generateJti(): string {
  return generateRandomBase64Url(16);
}

/**
 * Generate a unique key ID (kid) for signing keys
 */
export function generateKid(): string {
  return generateRandomBase64Url(12);
}

/**
 * Generate a unique ID for database records
 */
export function generateId(): string {
  return generateRandomBase64Url(16);
}

/**
 * Generate a token family ID for refresh token rotation tracking
 */
export function generateFamilyId(): string {
  return generateRandomBase64Url(16);
}
