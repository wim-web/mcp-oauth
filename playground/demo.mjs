import { OAuthProvider, MemoryStore } from './lib/mcp-oauth.js';
import { getAuth } from './lib/mcp-oauth-next.js';
import crypto from 'node:crypto';

const store = new MemoryStore();

// PKCE S256 helper
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
const pkce = generatePKCE();

let providerRef;
providerRef = new OAuthProvider({
  apiRoute: '/api/',
  apiHandler: {
    async fetch(request, ctx) {
      return new Response(JSON.stringify({ message: 'Hello from API!', user: ctx.props }), {
        headers: { 'Content-Type': 'application/json' },
      });
    },
  },
  defaultHandler: {
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === '/authorize') {
        // 自動承認 (デモ用)
        const authReq = await providerRef.parseAuthRequest(request);
        const { redirectTo } = await providerRef.completeAuthorization({
          request: authReq,
          userId: 'demo-user',
          metadata: {},
          scope: authReq.scope,
          props: { name: 'Demo User', role: 'admin' },
        });
        return Response.redirect(redirectTo, 302);
      }
      return new Response('Not Found', { status: 404 });
    },
  },
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
  scopesSupported: ['read', 'write'],
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400,
  storage: store,
});

console.log('=== OAuth 2.1 Flow Demo ===\n');

// 1. メタデータ取得
const metaRes = await providerRef.fetch(new Request('https://example.com/.well-known/oauth-authorization-server'));
const meta = await metaRes.json();
console.log('1. Server Metadata:', JSON.stringify(meta, null, 2), '\n');

// 2. クライアント登録
const regRes = await providerRef.fetch(new Request('https://example.com/oauth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    redirect_uris: ['https://client.example.com/callback'],
    client_name: 'Demo Client',
    token_endpoint_auth_method: 'client_secret_basic',
  }),
}));
const client = await regRes.json();
console.log('2. Client Registered:', { client_id: client.client_id, client_name: client.client_name }, '\n');

// 3. 認可リクエスト → リダイレクトでcode取得
const authUrl = `https://example.com/authorize?response_type=code&client_id=${client.client_id}&redirect_uri=${encodeURIComponent('https://client.example.com/callback')}&scope=read%20write&state=demo123&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
const authRes = await providerRef.fetch(new Request(authUrl));
const redirectUrl = new URL(authRes.headers.get('Location'));
const code = redirectUrl.searchParams.get('code');
const state = redirectUrl.searchParams.get('state');
console.log('3. Authorization Code:', code.slice(0, 20) + '...');
console.log('   State:', state, '\n');

// 4. トークン交換
const tokenParams = new URLSearchParams({
  grant_type: 'authorization_code',
  code,
  redirect_uri: 'https://client.example.com/callback',
  client_id: client.client_id,
  client_secret: client.client_secret,
  code_verifier: pkce.verifier,
});
const tokenRes = await providerRef.fetch(new Request('https://example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: tokenParams.toString(),
}));
const tokens = await tokenRes.json();
console.log('4. Tokens:', {
  access_token: tokens.access_token.slice(0, 20) + '...',
  token_type: tokens.token_type,
  expires_in: tokens.expires_in,
  has_refresh_token: !!tokens.refresh_token,
}, '\n');

// 5. API アクセス (Bearer トークン)
const apiRes = await providerRef.fetch(new Request('https://example.com/api/data', {
  headers: { Authorization: `Bearer ${tokens.access_token}` },
}));
const apiData = await apiRes.json();
console.log('5. API Response:', apiData, '\n');

// 6. getAuth (mcp-oauth/next)
const authResult = await getAuth(providerRef, new Request('https://example.com/api/data', {
  headers: { Authorization: `Bearer ${tokens.access_token}` },
}));
console.log('6. getAuth:', {
  authenticated: authResult.authenticated,
  props: authResult.authenticated ? authResult.token.grant.props : null,
}, '\n');

console.log('=== All OK! ===');
