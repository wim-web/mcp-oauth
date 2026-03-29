# @0x-wim/mcp-oauth

A platform-independent OAuth 2.1 provider library, forked from [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider). The primary goal of this fork is to remove Cloudflare Workers dependencies so the library can run on any platform (Next.js, Node.js, etc.).

## Installation

```bash
npm install @0x-wim/mcp-oauth
```

## Features

- OAuth 2.1 authorization code flow with PKCE
- Dynamic client registration (RFC 7591)
- Token exchange and refresh flows (RFC 8693)
- Protected resource metadata (RFC 9728)
- Client ID Metadata Document (CIMD) support
- Pluggable storage via `StorageAdapter` interface
- Next.js App Router helpers (`createOAuthHandlers`, `getAuth`)
- OIDC discovery and ID token verification helpers (`./oidc`)

## Storage

Instead of Cloudflare KV, this library uses a `StorageAdapter` interface:

```ts
import { OAuthProvider, MemoryStore } from '@0x-wim/mcp-oauth';

const provider = new OAuthProvider({
  storage: new MemoryStore(), // In-memory; replace with your own adapter for production
  // ... other options
});
```

`MemoryStore` is provided for development and testing only. For production, implement the `StorageAdapter` interface backed by Redis, a database, or any persistent store:

```ts
import type { StorageAdapter } from '@0x-wim/mcp-oauth';

class RedisAdapter implements StorageAdapter {
  async get(key: string): Promise<string | null> { /* ... */ }
  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> { /* ... */ }
  async delete(key: string): Promise<void> { /* ... */ }
  async list(options: { prefix: string; limit?: number; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }> { /* ... */ }
}
```

## Usage

### Basic setup

```ts
import { OAuthProvider, MemoryStore } from '@0x-wim/mcp-oauth';

const provider = new OAuthProvider({
  storage: new MemoryStore(),

  // API routes — requests with these URL prefixes require a valid access token
  apiRoute: ['/api/'],

  // Handler for authenticated API requests
  apiHandler: {
    async fetch(request, env, ctx) {
      // ctx.props contains what was passed to completeAuthorization()
      return new Response(`Hello, ${ctx.props.username}`);
    },
  },

  // Handler for all other requests (auth UI, etc.)
  defaultHandler: {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);

      if (url.pathname === '/authorize') {
        const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
        const clientInfo = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);

        // Render consent UI... then on approval:
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: oauthReqInfo,
          userId: '1234',
          metadata: { label: 'My App' },
          scope: oauthReqInfo.scope,
          props: { userId: 1234, username: 'Alice' },
        });

        return Response.redirect(redirectTo, 302);
      }

      return new Response('Not found', { status: 404 });
    },
  },

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
  scopesSupported: ['read', 'write'],
});

// Use provider.fetch(request) as your HTTP handler
export default provider;
```

### Multi-handler setup

Use `apiHandlers` to route different API paths to different handlers:

```ts
new OAuthProvider({
  // ...
  apiHandlers: {
    '/api/users/': UsersHandler,
    '/api/documents/': DocumentsHandler,
  },
});
```

## Next.js App Router

Use the `./next` entry point for Next.js App Router integration:

```ts
// app/[...oauth]/route.ts
import { createOAuthHandlers } from '@0x-wim/mcp-oauth/next';
import { provider } from '@/lib/oauth';

export const { GET, POST, OPTIONS, DELETE, PUT, PATCH } = createOAuthHandlers(provider);
```

### Authenticating requests

```ts
import { getAuth } from '@0x-wim/mcp-oauth/next';
import { provider } from '@/lib/oauth';

export async function GET(request: Request) {
  const auth = await getAuth(provider, request);

  if (!auth.authenticated) return auth.error;

  // auth.token.grant.props contains your user data
  return Response.json({ user: auth.token.grant.props });
}
```

`getAuth` also supports an optional `resolveExternalToken` callback for validating tokens issued by a third-party authorization server.

## OIDC Helpers

The `./oidc` entry point provides helpers for when your OAuth provider acts as an OIDC relying party (e.g., delegating login to Google, GitHub, etc.):

```ts
import { discoverOIDC, verifyIdToken, fetchUserInfo } from '@0x-wim/mcp-oauth/oidc';

// Discover OIDC configuration
const config = await discoverOIDC('https://accounts.google.com');

// Verify an ID token
const payload = await verifyIdToken(idToken, {
  jwks: config.jwks_uri,
  issuer: config.issuer,
  audience: 'your-client-id',
});

// Fetch user info
const userInfo = await fetchUserInfo(config.userinfo_endpoint!, accessToken);
```

## Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `storage` | `StorageAdapter` | — | **Required.** Token storage backend. |
| `apiRoute` | `string \| string[]` | — | URL prefixes requiring authentication. |
| `apiHandler` | handler | — | Handler for authenticated API requests. |
| `apiHandlers` | `Record<string, handler>` | — | Per-route handlers (alternative to `apiRoute`+`apiHandler`). |
| `defaultHandler` | handler | — | Handler for unauthenticated requests. |
| `authorizeEndpoint` | `string` | — | **Required.** Authorization UI URL or path. |
| `tokenEndpoint` | `string` | — | **Required.** Token exchange URL or path. |
| `clientRegistrationEndpoint` | `string` | — | Optional DCR endpoint. |
| `scopesSupported` | `string[]` | — | Scopes included in metadata. |
| `allowImplicitFlow` | `boolean` | `false` | Enable OAuth implicit flow (not recommended). |
| `allowPlainPKCE` | `boolean` | `true` | Allow `plain` PKCE method (S256 recommended). |
| `disallowPublicClientRegistration` | `boolean` | `false` | Restrict DCR to confidential clients only. |
| `refreshTokenTTL` | `number` | — | Refresh token TTL in seconds. `0` disables refresh tokens. |
| `accessTokenTTL` | `number` | `3600` | Access token TTL in seconds. |
| `allowTokenExchangeGrant` | `boolean` | `false` | Enable RFC 8693 token exchange grant. |
| `clientIdMetadataDocumentEnabled` | `boolean` | `false` | Enable CIMD (HTTPS URLs as client IDs). |
| `tokenExchangeCallback` | function | — | Callback to update `props` on token issuance/refresh. |
| `onError` | function | `console.warn` | Error handler; return a `Response` to override the default. |
| `resourceMetadata` | object | — | Override `/.well-known/oauth-protected-resource` fields. |

## Token Exchange Callback

Update `props` when tokens are issued or refreshed:

```ts
new OAuthProvider({
  // ...
  tokenExchangeCallback: async (options) => {
    // options.grantType: 'authorization_code' | 'refresh_token'
    // options.props, options.clientId, options.userId, options.scope

    const upstreamTokens = await exchangeUpstreamToken(options.props.code);
    return {
      accessTokenProps: { ...options.props, upstreamAccessToken: upstreamTokens.access_token },
      newProps: { ...options.props, upstreamRefreshToken: upstreamTokens.refresh_token },
      accessTokenTTL: upstreamTokens.expires_in,
    };
  },
});
```

Return values: `accessTokenProps`, `newProps`, `accessTokenTTL`, `refreshTokenTTL` (all optional).

## Custom Error Responses

```ts
new OAuthProvider({
  // ...
  onError({ code, description, status, headers }) {
    // Return a Response to override, or return nothing to use the default
    if (code === 'unsupported_grant_type') {
      return new Response('...', { status, headers });
    }
  },
});
```

## Protected Resource Metadata (RFC 9728)

The library automatically serves `/.well-known/oauth-protected-resource`. Customize with `resourceMetadata`:

```ts
new OAuthProvider({
  // ...
  resourceMetadata: {
    resource: 'https://api.example.com',
    authorization_servers: ['https://auth.example.com'],
    scopes_supported: ['read', 'write'],
  },
});
```

## Client ID Metadata Document (CIMD)

Allows HTTPS URLs as `client_id` values (fetched as metadata documents):

```ts
new OAuthProvider({
  // ...
  clientIdMetadataDocumentEnabled: true,
});
```

## Standards Compliance

- [OAuth 2.1 (draft-ietf-oauth-v2-1-13)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
- [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728)
- [OAuth 2.0 Dynamic Client Registration (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)
- [OAuth 2.0 Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693)
- [Resource Indicators for OAuth 2.0 (RFC 8707)](https://datatracker.ietf.org/doc/html/rfc8707)
- [OAuth Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## Implementation Notes

### End-to-end encryption

Token storage is designed so a complete storage leak reveals only mundane metadata:

- Secrets (access tokens, refresh tokens, auth codes, client secrets) are stored as SHA-256 hashes only.
- `props` are encrypted with AES-GCM using the secret token as key material — unreadable without a valid token.

`userId` and `metadata` are stored unencrypted to allow grant enumeration. Applications may apply their own encryption before passing these values in.

### Refresh token rotation

This library implements dual refresh tokens: at any time, both the current and the previous refresh token are valid. Using one invalidates the other and issues a new one. This handles transient network failures gracefully while still rotating tokens.

## License

MIT
