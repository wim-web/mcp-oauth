import { OAuthProvider, MemoryStore } from './lib/mcp-oauth.js';
import { createOAuthHandlers, getAuth } from './lib/mcp-oauth-next.js';
import { discoverOIDC, verifyIdToken, parseJwt } from './lib/mcp-oauth-oidc.js';

// Test: core import
const store = new MemoryStore();
const provider = new OAuthProvider({
  apiRoute: '/api/',
  apiHandler: { fetch: () => new Response('ok') },
  defaultHandler: { fetch: () => new Response('default') },
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  scopesSupported: ['read'],
  storage: store,
});
console.log('✓ core: OAuthProvider created');

// Test: next import
const handlers = createOAuthHandlers(provider);
console.log('✓ next: createOAuthHandlers returned', Object.keys(handlers).join(', '));

// Test: oidc import
const jwt = parseJwt(
  btoa(JSON.stringify({ alg: 'RS256' })).replace(/=/g, '') + '.' +
  btoa(JSON.stringify({ sub: 'test' })).replace(/=/g, '') + '.' +
  btoa('sig').replace(/=/g, '')
);
console.log('✓ oidc: parseJwt sub =', jwt.payload.sub);

console.log('\nAll imports work!');
