/**
 * Base64url decode a string to Uint8Array
 */
export function base64UrlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Base64url encode a Uint8Array to string
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** JWT header */
export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

/** Parsed JWT parts */
export interface ParsedJwt {
  header: JwtHeader;
  payload: Record<string, unknown>;
  headerB64: string;
  payloadB64: string;
  signature: Uint8Array;
}

/**
 * Parse a JWT string into its parts without verifying the signature
 */
export function parseJwt(token: string): ParsedJwt {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: expected 3 parts');
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  let header: JwtHeader;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
  } catch {
    throw new Error('Invalid JWT: malformed header');
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
  } catch {
    throw new Error('Invalid JWT: malformed payload');
  }

  return {
    header,
    payload,
    headerB64,
    payloadB64,
    signature: base64UrlDecode(signatureB64),
  };
}

/** JWK key from a JWKS */
export interface JwkKey {
  kty: string;
  use?: string;
  kid?: string;
  alg?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  crv?: string;
}

/** JWKS document */
export interface Jwks {
  keys: JwkKey[];
}

/**
 * Import a JWK as a CryptoKey for signature verification.
 * Supports RS256 and ES256.
 */
export async function importJwkForVerify(jwk: JwkKey, alg: string): Promise<CryptoKey> {
  if (alg === 'RS256') {
    return crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
  }

  if (alg === 'ES256') {
    return crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }

  throw new Error(`Unsupported algorithm: ${alg}`);
}

/**
 * Verify a JWT signature using Web Crypto API
 */
export async function verifySignature(
  alg: string,
  key: CryptoKey,
  signingInput: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  // Cast via new Uint8Array to get a clean ArrayBuffer for Web Crypto
  const sig = new Uint8Array(signature).buffer as ArrayBuffer;
  const data = new Uint8Array(signingInput).buffer as ArrayBuffer;

  if (alg === 'RS256') {
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  }

  if (alg === 'ES256') {
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data);
  }

  throw new Error(`Unsupported algorithm: ${alg}`);
}
