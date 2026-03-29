# @0x-wim/mcp-oauth

Platform-independent OAuth 2.1 provider, forked from [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) with Cloudflare dependencies removed. Runs on Next.js, Node.js, and any standard fetch environment.

## Installation

```bash
npm install @0x-wim/mcp-oauth
```

## Packages

| Entry point | Contents |
|---|---|
| `@0x-wim/mcp-oauth` | Core `OAuthProvider`, `MemoryStore`, `StorageAdapter` |
| `@0x-wim/mcp-oauth/next` | Next.js App Router helpers (`createOAuthHandlers`, `getAuth`) |
| `@0x-wim/mcp-oauth/oidc` | OIDC discovery and ID token verification |

## Storage

Instead of Cloudflare KV, supply a `StorageAdapter`. `MemoryStore` is provided for development:

```ts
import { OAuthProvider, MemoryStore } from '@0x-wim/mcp-oauth';

const provider = new OAuthProvider({
  storage: new MemoryStore(),
  // ...
});
```

For production, implement the `StorageAdapter` interface (`get`, `put`, `delete`, `list`) backed by Redis, a database, etc.

## Basic Usage

```ts
import { OAuthProvider, MemoryStore } from '@0x-wim/mcp-oauth';

const provider = new OAuthProvider({
  storage: new MemoryStore(),
  apiRoute: ['/api/'],
  apiHandler: {
    async fetch(request, env, ctx) {
      return new Response(`Hello, ${ctx.props.username}`);
    },
  },
  defaultHandler: {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      if (url.pathname === '/authorize') {
        const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
        // ... render consent UI ...
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: oauthReqInfo,
          userId: '1234',
          scope: oauthReqInfo.scope,
          props: { username: 'Alice' },
        });
        return Response.redirect(redirectTo, 302);
      }
      return new Response('Not found', { status: 404 });
    },
  },
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
});
```

## Next.js App Router

```ts
// app/[...oauth]/route.ts
import { createOAuthHandlers } from '@0x-wim/mcp-oauth/next';
export const { GET, POST, OPTIONS, DELETE, PUT, PATCH } = createOAuthHandlers(provider);
```

Authenticate requests in route handlers:

```ts
import { getAuth } from '@0x-wim/mcp-oauth/next';

const auth = await getAuth(provider, request);
if (!auth.authenticated) return auth.error;
// auth.token.grant.props — your user data
```

## OIDC Helpers

```ts
import { discoverOIDC, verifyIdToken, fetchUserInfo } from '@0x-wim/mcp-oauth/oidc';

const config = await discoverOIDC('https://accounts.google.com');
const payload = await verifyIdToken(idToken, {
  jwks: config.jwks_uri,
  issuer: config.issuer,
  audience: 'your-client-id',
});
```

## Key Options

See the upstream [README](https://github.com/cloudflare/workers-oauth-provider) for full option documentation. Differences from upstream:

- `storage: StorageAdapter` — **required** (replaces `OAUTH_KV` binding)
- No Cloudflare-specific setup needed (no `wrangler.jsonc`, no compatibility flags)

## Standards

OAuth 2.1 · RFC 8414 · RFC 9728 · RFC 7591 · RFC 8693 · RFC 8707 · [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## License

MIT
