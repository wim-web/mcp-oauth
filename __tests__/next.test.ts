import { describe, it, expect, beforeEach } from 'vitest';
import {
  createOAuthHandlers,
  getAuth,
  createGetAuth,
  OAuthProvider,
  MemoryStore,
  type OAuthContext,
  type ExternalAuthResult,
} from '../src/next';

// Simple API handler for testing
const testApiHandler = {
  async fetch(request: Request, ctx: OAuthContext) {
    return new Response(JSON.stringify({ success: true, user: ctx.props }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};

function createMockRequest(url: string, method = 'GET', headers: Record<string, string> = {}): Request {
  return new Request(url, { method, headers });
}

describe('createOAuthHandlers', () => {
  let provider: OAuthProvider;
  let memoryStore: MemoryStore;

  beforeEach(() => {
    memoryStore = new MemoryStore();
    provider = new OAuthProvider({
      apiRoute: '/api/',
      apiHandler: testApiHandler,
      defaultHandler: {
        async fetch() {
          return new Response('Default handler', { status: 200 });
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      scopesSupported: ['read', 'write'],
      storage: memoryStore,
    });
  });

  it('should return all HTTP method handlers', () => {
    const handlers = createOAuthHandlers(provider);

    expect(handlers.GET).toBeTypeOf('function');
    expect(handlers.POST).toBeTypeOf('function');
    expect(handlers.OPTIONS).toBeTypeOf('function');
    expect(handlers.DELETE).toBeTypeOf('function');
    expect(handlers.PUT).toBeTypeOf('function');
    expect(handlers.PATCH).toBeTypeOf('function');
  });

  it('should delegate GET to provider.fetch()', async () => {
    const handlers = createOAuthHandlers(provider);
    const request = createMockRequest('https://example.com/some-page');
    const response = await handlers.GET(request);

    // Default handler returns 200 for non-API routes
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('Default handler');
  });

  it('should delegate POST to provider.fetch()', async () => {
    const handlers = createOAuthHandlers(provider);

    // POST to a metadata endpoint triggers JSON response
    const request = createMockRequest('https://example.com/.well-known/oauth-authorization-server', 'POST');
    const response = await handlers.POST(request);
    // Metadata endpoint responds to GET; POST to non-matching path goes to default
    expect(response.status).toBe(200);
  });

  it('should handle OPTIONS for CORS preflight', async () => {
    const handlers = createOAuthHandlers(provider);
    const request = createMockRequest('https://example.com/.well-known/oauth-protected-resource', 'OPTIONS', {
      Origin: 'https://client.example.com',
      'Access-Control-Request-Method': 'GET',
    });

    const response = await handlers.OPTIONS(request);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeDefined();
  });
});

describe('getAuth', () => {
  let provider: OAuthProvider;
  let memoryStore: MemoryStore;
  let accessToken: string;

  beforeEach(async () => {
    memoryStore = new MemoryStore();

    let providerRef: OAuthProvider;
    providerRef = new OAuthProvider({
      apiRoute: '/api/',
      apiHandler: testApiHandler,
      defaultHandler: {
        async fetch(request: Request) {
          const url = new URL(request.url);
          if (url.pathname === '/authorize') {
            const oauthReqInfo = await providerRef.parseAuthRequest(request);
            const { redirectTo } = await providerRef.completeAuthorization({
              request: oauthReqInfo,
              userId: 'test-user-123',
              metadata: {},
              scope: oauthReqInfo.scope,
              props: { userId: 'test-user-123', role: 'admin' },
            });
            return Response.redirect(redirectTo, 302);
          }
          return new Response('OK', { status: 200 });
        },
      },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint: '/oauth/register',
      scopesSupported: ['read', 'write'],
      accessTokenTTL: 3600,
      allowPlainPKCE: true,
      refreshTokenTTL: 86400,
      storage: memoryStore,
    });
    provider = providerRef;

    // Register a client
    const registerResponse = await provider.fetch(
      new Request('https://example.com/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://client.example.com/callback'],
          client_name: 'Test Client',
          token_endpoint_auth_method: 'client_secret_basic',
        }),
      })
    );
    const client = (await registerResponse.json()) as any;

    // Authorize
    const authResponse = await provider.fetch(
      createMockRequest(
        `https://example.com/authorize?response_type=code&client_id=${client.client_id}` +
          `&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&scope=read%20write&state=xyz`
      )
    );
    const code = new URL(authResponse.headers.get('Location')!).searchParams.get('code')!;

    // Exchange for tokens
    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', 'https://client.example.com/callback');
    params.append('client_id', client.client_id);
    params.append('client_secret', client.client_secret);

    const tokenResponse = await provider.fetch(
      new Request('https://example.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      })
    );
    const tokens = (await tokenResponse.json()) as any;
    accessToken = tokens.access_token;
  });

  it('should return authenticated result with valid token', async () => {
    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: `Bearer ${accessToken}`,
    });

    const result = await getAuth(provider, request);

    expect(result.authenticated).toBe(true);
    if (result.authenticated) {
      expect(result.token.grant.props.userId).toBe('test-user-123');
      expect(result.token.grant.props.role).toBe('admin');
    }
  });

  it('should return failure when Authorization header is missing', async () => {
    const request = createMockRequest('https://example.com/api/data');
    const result = await getAuth(provider, request);

    expect(result.authenticated).toBe(false);
    if (!result.authenticated) {
      expect(result.error.status).toBe(401);
      expect(result.error.headers.get('WWW-Authenticate')).toBe('Bearer');
    }
  });

  it('should return failure with invalid token', async () => {
    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: 'Bearer invalid-token',
    });

    const result = await getAuth(provider, request);

    expect(result.authenticated).toBe(false);
    if (!result.authenticated) {
      expect(result.error.status).toBe(401);
      expect(result.error.headers.get('WWW-Authenticate')).toContain('invalid_token');
    }
  });

  it('should return failure when Authorization header is not Bearer', async () => {
    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: 'Basic dXNlcjpwYXNz',
    });

    const result = await getAuth(provider, request);

    expect(result.authenticated).toBe(false);
    if (!result.authenticated) {
      expect(result.error.status).toBe(401);
    }
  });

  it('should resolve external token via resolveExternalToken callback', async () => {
    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: 'Bearer external-opaque-token',
    });

    const result = await getAuth(provider, request, {
      resolveExternalToken: async ({ token }) => {
        if (token === 'external-opaque-token') {
          return { props: { sub: 'ext-user', plan: 'pro' } };
        }
        return null;
      },
    });

    expect(result.authenticated).toBe(true);
    if (result.authenticated) {
      const ext = result as ExternalAuthResult;
      expect(ext.external).toBe(true);
      expect(ext.props.sub).toBe('ext-user');
      expect(ext.props.plan).toBe('pro');
    }
  });

  it('should reject external token when audience does not match', async () => {
    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: 'Bearer external-audience-token',
    });

    const result = await getAuth(provider, request, {
      resolveExternalToken: async () => {
        return {
          props: { sub: 'ext-user' },
          audience: 'https://other-server.example.com/api',
        };
      },
    });

    expect(result.authenticated).toBe(false);
    if (!result.authenticated) {
      expect(result.error.status).toBe(401);
      const body = (await result.error.json()) as any;
      expect(body.error_description).toContain('audience');
    }
  });

  it('should resolve external token via createGetAuth factory', async () => {
    const resolver = async ({ token }: { token: string }) => {
      if (token === 'factory-ext-token') {
        return { props: { sub: 'factory-user' } };
      }
      return null;
    };

    const authChecker = createGetAuth(provider, { resolveExternalToken: resolver });

    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: 'Bearer factory-ext-token',
    });

    const result = await authChecker(request);

    expect(result.authenticated).toBe(true);
    if (result.authenticated) {
      const ext = result as ExternalAuthResult;
      expect(ext.external).toBe(true);
      expect(ext.props.sub).toBe('factory-user');
    }
  });

  it('should support generic type parameter', async () => {
    interface MyProps {
      userId: string;
      role: string;
    }

    const request = createMockRequest('https://example.com/api/data', 'GET', {
      Authorization: `Bearer ${accessToken}`,
    });

    const result = await getAuth<MyProps>(provider, request);

    expect(result.authenticated).toBe(true);
    if (result.authenticated) {
      // TypeScript knows token.props is MyProps
      expect(result.token.grant.props.userId).toBe('test-user-123');
      expect(result.token.grant.props.role).toBe('admin');
    }
  });
});
