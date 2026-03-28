import { type Jwks, type JwkKey, parseJwt, importJwkForVerify, verifySignature } from './jwt-utils';

/** ID Token claims */
export interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  auth_time?: number;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  [key: string]: unknown;
}

/** Options for ID token verification */
export interface VerifyIdTokenOptions {
  /** JWKS endpoint URL or pre-fetched JWKS object */
  jwks: string | Jwks;
  /** Expected issuer (must match iss claim) */
  issuer: string;
  /** Expected audience (must match aud claim) */
  audience: string;
  /** Expected nonce (must match nonce claim if provided) */
  nonce?: string;
  /** Clock skew tolerance in seconds. Defaults to 60. */
  clockToleranceSec?: number;
  /** Allowed algorithms. Defaults to ['RS256', 'ES256']. */
  algorithms?: string[];
  /** Custom fetch function (for testing) */
  fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds for JWKS fetch. Defaults to 10000. */
  timeoutMs?: number;
  /** Current unix timestamp in seconds (for testing). Defaults to Date.now()/1000. */
  now?: number;
}

/**
 * Fetch a JWKS from a URL with timeout
 */
async function fetchJwks(
  jwksUri: string,
  fetchFn: typeof globalThis.fetch,
  timeoutMs: number
): Promise<Jwks> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchFn(jwksUri, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`JWKS fetch failed: HTTP ${response.status}`);
    }
    return (await response.json()) as Jwks;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Find a matching key in JWKS by kid and alg
 */
function findKey(jwks: Jwks, kid: string | undefined, alg: string): JwkKey | undefined {
  return jwks.keys.find((key) => {
    if (kid && key.kid !== kid) return false;
    if (key.alg && key.alg !== alg) return false;
    if (key.use && key.use !== 'sig') return false;
    // Match key type to algorithm
    if (alg === 'RS256' && key.kty !== 'RSA') return false;
    if (alg === 'ES256' && key.kty !== 'EC') return false;
    return true;
  });
}

/**
 * Verify an OIDC ID token.
 *
 * 1. Parse JWT (header.payload.signature)
 * 2. Fetch JWKS (from URL or use provided object)
 * 3. Find matching key by kid and alg
 * 4. Verify signature using Web Crypto API
 * 5. Validate claims (iss, aud, exp, iat, nonce)
 */
export async function verifyIdToken(
  token: string,
  options: VerifyIdTokenOptions
): Promise<IdTokenPayload> {
  const fetchFn = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 10000;
  const clockTolerance = options.clockToleranceSec ?? 60;
  const allowedAlgs = options.algorithms ?? ['RS256', 'ES256'];
  const now = options.now ?? Math.floor(Date.now() / 1000);

  // 1. Parse JWT
  const jwt = parseJwt(token);

  // 2. Validate algorithm
  if (!allowedAlgs.includes(jwt.header.alg)) {
    throw new Error(`Unsupported algorithm: ${jwt.header.alg}. Allowed: ${allowedAlgs.join(', ')}`);
  }

  // 3. Get JWKS
  let jwks: Jwks;
  if (typeof options.jwks === 'string') {
    jwks = await fetchJwks(options.jwks, fetchFn, timeoutMs);
  } else {
    jwks = options.jwks;
  }

  // 4. Find matching key
  let jwk = findKey(jwks, jwt.header.kid, jwt.header.alg);

  // If not found and JWKS was fetched from URL, try refetching (key rotation)
  if (!jwk && typeof options.jwks === 'string') {
    jwks = await fetchJwks(options.jwks, fetchFn, timeoutMs);
    jwk = findKey(jwks, jwt.header.kid, jwt.header.alg);
  }

  if (!jwk) {
    throw new Error(`No matching key found in JWKS for kid=${jwt.header.kid}, alg=${jwt.header.alg}`);
  }

  // 5. Verify signature
  const cryptoKey = await importJwkForVerify(jwk, jwt.header.alg);
  const signingInput = new TextEncoder().encode(`${jwt.headerB64}.${jwt.payloadB64}`);
  const valid = await verifySignature(jwt.header.alg, cryptoKey, signingInput, jwt.signature);

  if (!valid) {
    throw new Error('Invalid signature');
  }

  // 6. Validate claims
  const payload = jwt.payload as IdTokenPayload;

  if (payload.iss !== options.issuer) {
    throw new Error(`Issuer mismatch: expected ${options.issuer}, got ${payload.iss}`);
  }

  const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audArray.includes(options.audience)) {
    throw new Error(`Audience mismatch: expected ${options.audience}, got ${payload.aud}`);
  }

  if (payload.exp === undefined || now - clockTolerance >= payload.exp) {
    throw new Error('Token has expired');
  }

  if (payload.iat !== undefined && payload.iat > now + clockTolerance) {
    throw new Error('Token issued in the future');
  }

  if (options.nonce !== undefined && payload.nonce !== options.nonce) {
    throw new Error(`Nonce mismatch: expected ${options.nonce}, got ${payload.nonce}`);
  }

  return payload;
}
