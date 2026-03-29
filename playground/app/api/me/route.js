import { getAuth } from '../../../lib/mcp-oauth-next.js';
import { provider } from '../../../lib/provider.js';

export async function GET(request) {
  const auth = await getAuth(provider, request);
  if (!auth.authenticated) return auth.error;

  return new Response(JSON.stringify({ user: auth.token.grant.props }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
