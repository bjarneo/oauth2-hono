import { createHash, timingSafeEqual, randomBytes, scrypt as scryptCallback } from 'node:crypto';

/**
 * Promisified scrypt function
 */
function scryptAsync(
  password: string,
  salt: Buffer,
  keyLength: number,
  options: { N: number; r: number; p: number }
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keyLength, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Hash a value using SHA-256 (for tokens, codes)
 * Used for storing authorization codes, refresh tokens, device codes
 */
export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Hash a value using SHA-256 and return as base64url
 */
export function sha256Base64Url(value: string): string {
  return createHash('sha256')
    .update(value, 'utf8')
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Compare two strings in constant time to prevent timing attacks
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  return timingSafeEqual(bufA, bufB);
}

/**
 * Hash a client secret using scrypt (more secure for long-term storage)
 * Returns format: $scrypt$N$r$p$salt$hash
 */
export async function hashClientSecret(secret: string): Promise<string> {
  const salt = randomBytes(16);
  const N = 16384; // CPU/memory cost
  const r = 8; // Block size
  const p = 1; // Parallelization
  const keyLength = 64;

  const hash = (await scryptAsync(secret, salt, keyLength, { N, r, p })) as Buffer;

  return `$scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/**
 * Verify a client secret against its hash
 */
export async function verifyClientSecret(secret: string, hash: string): Promise<boolean> {
  const parts = hash.split('$');

  // Expected format: $scrypt$N$r$p$salt$hash
  if (parts.length !== 7 || parts[1] !== 'scrypt') {
    return false;
  }

  const N = parseInt(parts[2]!, 10);
  const r = parseInt(parts[3]!, 10);
  const p = parseInt(parts[4]!, 10);
  const salt = Buffer.from(parts[5]!, 'base64');
  const storedHash = Buffer.from(parts[6]!, 'base64');

  const derivedHash = (await scryptAsync(secret, salt, storedHash.length, { N, r, p })) as Buffer;

  return timingSafeEqual(storedHash, derivedHash);
}

/**
 * Hash for token comparison (quick hash, not for long-term storage)
 * Used for comparing tokens that are already random and high-entropy
 */
export function hashToken(token: string): string {
  return sha256(token);
}

/**
 * Verify a token against its hash
 */
export function verifyTokenHash(token: string, hash: string): boolean {
  const tokenHash = sha256(token);
  return constantTimeCompare(tokenHash, hash);
}
