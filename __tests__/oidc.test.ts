import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  discoverOIDC,
  verifyIdToken,
  fetchUserInfo,
  parseJwt,
  base64UrlEncode,
  base64UrlDecode,
  type Jwks,
} from '../src/oidc/index';

// Helper to create a mock fetch that returns a JSON response
function mockJsonFetch(body: unknown, status = 200): typeof globalThis.fetch {
  return vi.fn().mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })
    )
  ) as unknown as typeof globalThis.fetch;
}

// Valid OIDC config fixture
const validOidcConfig = {
  issuer: 'https://idp.example.com',
  authorization_endpoint: 'https://idp.example.com/authorize',
  token_endpoint: 'https://idp.example.com/token',
  userinfo_endpoint: 'https://idp.example.com/userinfo',
  jwks_uri: 'https://idp.example.com/.well-known/jwks.json',
  response_types_supported: ['code', 'id_token'],
  id_token_signing_alg_values_supported: ['RS256', 'ES256'],
};

describe('discoverOIDC', () => {
  it('should fetch and parse OIDC configuration', async () => {
    const fetchMock = mockJsonFetch(validOidcConfig);
    const config = await discoverOIDC('https://idp.example.com', { fetch: fetchMock });

    expect(config.issuer).toBe('https://idp.example.com');
    expect(config.authorization_endpoint).toBe('https://idp.example.com/authorize');
    expect(config.jwks_uri).toBe('https://idp.example.com/.well-known/jwks.json');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://idp.example.com/.well-known/openid-configuration',
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    );
  });

  it('should handle trailing slash in issuer URL', async () => {
    const fetchMock = mockJsonFetch(validOidcConfig);
    await discoverOIDC('https://idp.example.com/', { fetch: fetchMock });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://idp.example.com/.well-known/openid-configuration',
      expect.anything()
    );
  });

  it('should throw on issuer mismatch', async () => {
    const mismatchedConfig = { ...validOidcConfig, issuer: 'https://evil.example.com' };
    const fetchMock = mockJsonFetch(mismatchedConfig);

    await expect(discoverOIDC('https://idp.example.com', { fetch: fetchMock })).rejects.toThrow('OIDC issuer mismatch');
  });

  it('should throw on missing required fields', async () => {
    const incompleteConfig = { issuer: 'https://idp.example.com' };
    const fetchMock = mockJsonFetch(incompleteConfig);

    await expect(discoverOIDC('https://idp.example.com', { fetch: fetchMock })).rejects.toThrow(
      'missing required field'
    );
  });

  it('should throw on HTTP error', async () => {
    const fetchMock = mockJsonFetch({ error: 'not found' }, 404);

    await expect(discoverOIDC('https://idp.example.com', { fetch: fetchMock })).rejects.toThrow('HTTP 404');
  });

  it('should throw on network error', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('Connection refused')) as unknown as typeof globalThis.fetch;

    await expect(discoverOIDC('https://idp.example.com', { fetch: fetchMock })).rejects.toThrow('Connection refused');
  });
});

// Helper to generate RS256 key pair and create a signed JWT
async function createSignedJwt(
  payload: Record<string, unknown>,
  keyPair: CryptoKeyPair,
  alg: 'RS256' | 'ES256',
  kid = 'test-key-1'
): Promise<{ token: string; jwks: Jwks }> {
  const header = { alg, typ: 'JWT', kid };
  const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const algParams = alg === 'RS256' ? 'RSASSA-PKCS1-v1_5' : { name: 'ECDSA', hash: 'SHA-256' };
  const signature = await crypto.subtle.sign(algParams, keyPair.privateKey, signingInput);
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  return {
    token: `${headerB64}.${payloadB64}.${signatureB64}`,
    jwks: { keys: [{ ...publicJwk, kid, use: 'sig' } as any] },
  };
}

async function generateRS256KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
}

async function generateES256KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

describe('verifyIdToken', () => {
  const now = Math.floor(Date.now() / 1000);
  const validClaims = {
    iss: 'https://idp.example.com',
    sub: 'user-123',
    aud: 'my-client-id',
    exp: now + 3600,
    iat: now - 10,
    nonce: 'test-nonce',
    email: 'user@example.com',
  };

  it('should verify a valid RS256 ID token', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');

    const payload = await verifyIdToken(token, {
      jwks,
      issuer: 'https://idp.example.com',
      audience: 'my-client-id',
      now,
    });

    expect(payload.sub).toBe('user-123');
    expect(payload.email).toBe('user@example.com');
  });

  it('should verify a valid ES256 ID token', async () => {
    const keyPair = await generateES256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'ES256');

    const payload = await verifyIdToken(token, {
      jwks,
      issuer: 'https://idp.example.com',
      audience: 'my-client-id',
      now,
    });

    expect(payload.sub).toBe('user-123');
  });

  it('should reject an expired token', async () => {
    const keyPair = await generateRS256KeyPair();
    const expiredClaims = { ...validClaims, exp: now - 3600 };
    const { token, jwks } = await createSignedJwt(expiredClaims, keyPair, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://idp.example.com',
        audience: 'my-client-id',
        now,
      })
    ).rejects.toThrow('Token has expired');
  });

  it('should accept nearly-expired token within clock tolerance', async () => {
    const keyPair = await generateRS256KeyPair();
    const almostExpiredClaims = { ...validClaims, exp: now - 30 };
    const { token, jwks } = await createSignedJwt(almostExpiredClaims, keyPair, 'RS256');

    // Default clock tolerance is 60 seconds
    const payload = await verifyIdToken(token, {
      jwks,
      issuer: 'https://idp.example.com',
      audience: 'my-client-id',
      now,
    });

    expect(payload.sub).toBe('user-123');
  });

  it('should reject wrong issuer', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://wrong.example.com',
        audience: 'my-client-id',
        now,
      })
    ).rejects.toThrow('Issuer mismatch');
  });

  it('should reject wrong audience', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://idp.example.com',
        audience: 'wrong-client-id',
        now,
      })
    ).rejects.toThrow('Audience mismatch');
  });

  it('should reject invalid signature', async () => {
    const keyPair1 = await generateRS256KeyPair();
    const keyPair2 = await generateRS256KeyPair();
    const { token } = await createSignedJwt(validClaims, keyPair1, 'RS256');
    const { jwks: wrongJwks } = await createSignedJwt(validClaims, keyPair2, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks: wrongJwks,
        issuer: 'https://idp.example.com',
        audience: 'my-client-id',
        now,
      })
    ).rejects.toThrow('Invalid signature');
  });

  it('should reject unknown kid', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256', 'key-1');

    // Modify jwks to have a different kid
    jwks.keys[0].kid = 'different-kid';

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://idp.example.com',
        audience: 'my-client-id',
        now,
      })
    ).rejects.toThrow('No matching key found');
  });

  it('should verify nonce when provided', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://idp.example.com',
        audience: 'my-client-id',
        nonce: 'wrong-nonce',
        now,
      })
    ).rejects.toThrow('Nonce mismatch');
  });

  it('should accept token with array audience', async () => {
    const keyPair = await generateRS256KeyPair();
    const multiAudClaims = { ...validClaims, aud: ['my-client-id', 'other-client'] };
    const { token, jwks } = await createSignedJwt(multiAudClaims, keyPair, 'RS256');

    const payload = await verifyIdToken(token, {
      jwks,
      issuer: 'https://idp.example.com',
      audience: 'my-client-id',
      now,
    });

    expect(payload.sub).toBe('user-123');
  });

  it('should fetch JWKS from URL when string is provided', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');
    const fetchMock = mockJsonFetch(jwks);

    const payload = await verifyIdToken(token, {
      jwks: 'https://idp.example.com/.well-known/jwks.json',
      issuer: 'https://idp.example.com',
      audience: 'my-client-id',
      fetch: fetchMock,
      now,
    });

    expect(payload.sub).toBe('user-123');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('should reject unsupported algorithm', async () => {
    const keyPair = await generateRS256KeyPair();
    const { token, jwks } = await createSignedJwt(validClaims, keyPair, 'RS256');

    await expect(
      verifyIdToken(token, {
        jwks,
        issuer: 'https://idp.example.com',
        audience: 'my-client-id',
        algorithms: ['ES256'],
        now,
      })
    ).rejects.toThrow('Unsupported algorithm: RS256');
  });
});

describe('fetchUserInfo', () => {
  it('should fetch user info with Bearer token', async () => {
    const userInfo = { sub: 'user-123', name: 'Test User', email: 'test@example.com' };
    const fetchMock = mockJsonFetch(userInfo);

    const result = await fetchUserInfo('my-access-token', 'https://idp.example.com/userinfo', {
      fetch: fetchMock,
    });

    expect(result.sub).toBe('user-123');
    expect(result.name).toBe('Test User');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://idp.example.com/userinfo',
      expect.objectContaining({
        headers: { Authorization: 'Bearer my-access-token' },
      })
    );
  });

  it('should throw on HTTP error', async () => {
    const fetchMock = mockJsonFetch({ error: 'unauthorized' }, 401);

    await expect(fetchUserInfo('bad-token', 'https://idp.example.com/userinfo', { fetch: fetchMock })).rejects.toThrow(
      'HTTP 401'
    );
  });

  it('should throw on missing sub claim', async () => {
    const fetchMock = mockJsonFetch({ name: 'No Sub User' });

    await expect(fetchUserInfo('token', 'https://idp.example.com/userinfo', { fetch: fetchMock })).rejects.toThrow(
      'missing required field: sub'
    );
  });

  it('should throw on network error', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('Network failure')) as unknown as typeof globalThis.fetch;

    await expect(fetchUserInfo('token', 'https://idp.example.com/userinfo', { fetch: fetchMock })).rejects.toThrow(
      'Network failure'
    );
  });
});

describe('parseJwt', () => {
  it('should parse a valid JWT', () => {
    const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
    const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ sub: 'test' })));
    const signature = base64UrlEncode(new Uint8Array([1, 2, 3]));
    const token = `${header}.${payload}.${signature}`;

    const parsed = parseJwt(token);
    expect(parsed.header.alg).toBe('RS256');
    expect(parsed.payload.sub).toBe('test');
  });

  it('should throw on invalid JWT format', () => {
    expect(() => parseJwt('not-a-jwt')).toThrow('expected 3 parts');
  });
});

describe('base64url', () => {
  it('should roundtrip encode/decode', () => {
    const original = new Uint8Array([0, 1, 255, 128, 64]);
    const encoded = base64UrlEncode(original);
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(original);
  });
});
