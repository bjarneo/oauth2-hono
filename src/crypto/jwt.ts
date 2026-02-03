import * as jose from 'jose';
import type { AccessTokenPayload, IdTokenPayload } from '../types/token.js';
import type { SigningKey } from '../types/tenant.js';
import { generateJti } from './random.js';

/**
 * JWT signing and verification utilities using jose library
 */

type SigningAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';

/**
 * Import a private key from PEM format
 */
async function importPrivateKey(
  pem: string,
  algorithm: SigningAlgorithm
): Promise<jose.KeyLike> {
  return jose.importPKCS8(pem, algorithm);
}

/**
 * Import a public key from PEM format
 */
async function importPublicKey(
  pem: string,
  algorithm: SigningAlgorithm
): Promise<jose.KeyLike> {
  return jose.importSPKI(pem, algorithm);
}

/**
 * Sign a JWT access token
 */
export async function signAccessToken(
  payload: Omit<AccessTokenPayload, 'jti'>,
  signingKey: SigningKey
): Promise<string> {
  const privateKey = await importPrivateKey(signingKey.privateKey, signingKey.algorithm);

  const jwt = await new jose.SignJWT({
    ...payload,
    jti: generateJti(),
    token_type: 'access_token',
  } as unknown as jose.JWTPayload)
    .setProtectedHeader({
      alg: signingKey.algorithm,
      kid: signingKey.kid,
      typ: 'at+jwt', // RFC 9068 JWT Profile for OAuth 2.0 Access Tokens
    })
    .sign(privateKey);

  return jwt;
}

/**
 * Sign a JWT ID token
 */
export async function signIdToken(
  payload: IdTokenPayload,
  signingKey: SigningKey
): Promise<string> {
  const privateKey = await importPrivateKey(signingKey.privateKey, signingKey.algorithm);

  const jwt = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
    .setProtectedHeader({
      alg: signingKey.algorithm,
      kid: signingKey.kid,
      typ: 'JWT',
    })
    .sign(privateKey);

  return jwt;
}

/**
 * Verify and decode a JWT
 */
export async function verifyJwt<T extends jose.JWTPayload>(
  token: string,
  publicKey: string,
  algorithm: SigningAlgorithm,
  options: {
    issuer?: string;
    audience?: string | string[];
    clockTolerance?: number;
  } = {}
): Promise<T> {
  const key = await importPublicKey(publicKey, algorithm);

  const verifyOptions: jose.JWTVerifyOptions = {
    clockTolerance: options.clockTolerance ?? 5,
  };

  if (options.issuer) {
    verifyOptions.issuer = options.issuer;
  }

  if (options.audience) {
    verifyOptions.audience = options.audience;
  }

  const { payload } = await jose.jwtVerify(token, key, verifyOptions);

  return payload as T;
}

/**
 * Decode a JWT without verification (for introspection)
 * WARNING: Only use this when you've already verified the token or for debugging
 */
export function decodeJwt<T extends jose.JWTPayload>(token: string): T | null {
  try {
    const payload = jose.decodeJwt(token);
    return payload as T;
  } catch {
    return null;
  }
}

/**
 * Get the JWT header without verification
 */
export function getJwtHeader(token: string): jose.JWTHeaderParameters | null {
  try {
    const header = jose.decodeProtectedHeader(token);
    return header as jose.JWTHeaderParameters;
  } catch {
    return null;
  }
}

/**
 * Generate a new RSA key pair for signing
 */
export async function generateRsaKeyPair(
  algorithm: 'RS256' | 'RS384' | 'RS512' = 'RS256'
): Promise<{ publicKey: string; privateKey: string }> {
  const modulusLength = algorithm === 'RS512' ? 4096 : 2048;

  const { publicKey, privateKey } = await jose.generateKeyPair(algorithm, {
    modulusLength,
    extractable: true,
  });

  const publicKeyPem = await jose.exportSPKI(publicKey);
  const privateKeyPem = await jose.exportPKCS8(privateKey);

  return {
    publicKey: publicKeyPem,
    privateKey: privateKeyPem,
  };
}

/**
 * Generate a new EC key pair for signing
 */
export async function generateEcKeyPair(
  algorithm: 'ES256' | 'ES384' | 'ES512' = 'ES256'
): Promise<{ publicKey: string; privateKey: string }> {
  const { publicKey, privateKey } = await jose.generateKeyPair(algorithm, {
    extractable: true,
  });

  const publicKeyPem = await jose.exportSPKI(publicKey);
  const privateKeyPem = await jose.exportPKCS8(privateKey);

  return {
    publicKey: publicKeyPem,
    privateKey: privateKeyPem,
  };
}

/**
 * Convert a PEM public key to JWK format (for JWKS endpoint)
 */
export async function publicKeyToJwk(
  publicKeyPem: string,
  kid: string,
  algorithm: SigningAlgorithm
): Promise<jose.JWK> {
  const publicKey = await importPublicKey(publicKeyPem, algorithm);
  const jwk = await jose.exportJWK(publicKey);

  return {
    ...jwk,
    kid,
    alg: algorithm,
    use: 'sig',
  };
}

/**
 * Verify a client assertion JWT (for private_key_jwt authentication)
 */
export async function verifyClientAssertion(
  assertion: string,
  clientJwks: jose.JSONWebKeySet,
  options: {
    issuer: string; // client_id
    audience: string; // token endpoint URL
    maxAge?: number;
  }
): Promise<jose.JWTPayload> {
  const jwks = jose.createLocalJWKSet(clientJwks);

  const { payload } = await jose.jwtVerify(assertion, jwks, {
    issuer: options.issuer,
    audience: options.audience,
    maxTokenAge: options.maxAge ?? 300, // 5 minutes default
  });

  return payload;
}
