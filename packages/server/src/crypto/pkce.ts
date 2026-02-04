import { sha256Base64Url } from './hash.js';

/**
 * Generate a code challenge from a code verifier using S256 method
 * RFC 7636 Section 4.2
 *
 * code_challenge = BASE64URL(SHA256(code_verifier))
 */
export function generateCodeChallenge(codeVerifier: string): string {
  return sha256Base64Url(codeVerifier);
}

/**
 * Verify a code verifier against a stored code challenge
 * RFC 7636 Section 4.6
 *
 * Only S256 method is supported per RFC 9700
 */
export function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
  method: 'S256'
): boolean {
  if (method !== 'S256') {
    return false;
  }

  const computedChallenge = generateCodeChallenge(codeVerifier);
  return computedChallenge === codeChallenge;
}

/**
 * Validate code verifier format
 * RFC 7636 Section 4.1
 *
 * code_verifier = high-entropy cryptographic random STRING
 * using the unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 * with a minimum length of 43 characters and a maximum length of 128 characters
 */
export function isValidCodeVerifier(codeVerifier: string): boolean {
  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false;
  }

  // RFC 7636 unreserved characters
  const validPattern = /^[A-Za-z0-9\-._~]+$/;
  return validPattern.test(codeVerifier);
}

/**
 * Validate code challenge format
 * Must be base64url-encoded without padding
 * For S256: 43 characters (256 bits / 6 bits per base64 char = ~43)
 */
export function isValidCodeChallenge(codeChallenge: string): boolean {
  // S256 produces a 32-byte hash, which is 43 base64url characters
  if (codeChallenge.length !== 43) {
    return false;
  }

  // base64url characters without padding
  const validPattern = /^[A-Za-z0-9\-_]+$/;
  return validPattern.test(codeChallenge);
}
