import { OAuthProvider, MemoryStore } from './mcp-oauth.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod/v4';

const store = new MemoryStore();

// --- MCP ---
function createMcpServer() {
  const server = new McpServer({ name: 'hello-mcp', version: '1.0.0' });

  server.tool('hello', 'Say hello to someone', { name: z.string() }, async ({ name }) => ({
    content: [{ type: 'text', text: `Hello, ${name}!` }],
  }));

  server.tool('whoami', 'Show current user info', {}, async (_args, extra) => ({
    content: [{ type: 'text', text: JSON.stringify(extra.authInfo, null, 2) }],
  }));

  return server;
}

const mcpTransports = new Map();

// CORS headers needed for browser clients to read mcp-session-id
// See: https://github.com/modelcontextprotocol/inspector/issues/905
const CORS_HEADERS = {
  'Access-Control-Expose-Headers': 'Mcp-Session-Id',
};

function addCorsToResponse(response) {
  const newResponse = new Response(response.body, response);
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    newResponse.headers.set(k, v);
  }
  return newResponse;
}

// --- OAuth Provider ---
let providerRef;
providerRef = new OAuthProvider({
  apiRoute: '/mcp',
  apiHandler: {
    async fetch(request, ctx) {
      try {
        const sessionId = request.headers.get('mcp-session-id');
        let transport;

        if (sessionId && mcpTransports.has(sessionId)) {
          transport = mcpTransports.get(sessionId);
        } else if (request.method === 'POST') {
          transport = new WebStandardStreamableHTTPServerTransport({
            sessionIdGenerator: () => crypto.randomUUID(),
            onsessioninitialized: (sid) => mcpTransports.set(sid, transport),
            onsessionclosed: (sid) => mcpTransports.delete(sid),
          });
          const mcpServer = createMcpServer();
          await mcpServer.connect(transport);
        } else if (request.method === 'GET') {
          return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'No active session. Send POST with initialize first.' }, id: null }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        } else if (request.method === 'DELETE') {
          if (sessionId && mcpTransports.has(sessionId)) {
            mcpTransports.delete(sessionId);
            return new Response(null, { status: 204 });
          }
          return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Session not found' }, id: null }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        } else {
          return new Response('Method not allowed', { status: 405 });
        }

        const response = await transport.handleRequest(request, {
          authInfo: { userId: ctx.props?.name ?? 'unknown', ...ctx.props },
        });

        // For GET SSE: inject a comment to flush headers so clients don't hang
        if (request.method === 'GET' && response.headers.get('content-type')?.includes('text/event-stream') && response.body) {
          const original = response.body;
          const injected = new ReadableStream({
            async start(controller) {
              controller.enqueue(new TextEncoder().encode(':ok\n\n'));
              const reader = original.getReader();
              try {
                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  controller.enqueue(value);
                }
                controller.close();
              } catch (e) {
                controller.error(e);
              }
            },
            cancel() {
              original.cancel();
            },
          });
          return addCorsToResponse(new Response(injected, {
            status: response.status,
            headers: response.headers,
          }));
        }

        return addCorsToResponse(response);
      } catch (e) {
        console.error('MCP handler error:', e);
        return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: e.message }, id: null }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    },
  },
  defaultHandler: {
    async fetch(request) {
      const url = new URL(request.url);

      if (url.pathname === '/oauth/authorize' && request.method === 'GET') {
        let authReq;
        try {
          authReq = await providerRef.parseAuthRequest(request);
        } catch (e) {
          return new Response(`<h1>Error</h1><p>${e.message}</p>`, {
            status: 400,
            headers: { 'Content-Type': 'text/html' },
          });
        }
        const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize</title>
<style>
  body { font-family: system-ui; max-width: 480px; margin: 60px auto; padding: 0 20px; }
  .card { border: 1px solid #ddd; border-radius: 12px; padding: 32px; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  .client { color: #666; margin-bottom: 24px; }
  .scopes { margin: 16px 0; }
  .scope { display: inline-block; background: #f0f0f0; padding: 4px 12px; border-radius: 6px; margin: 4px; font-size: 14px; }
  .actions { display: flex; gap: 12px; margin-top: 24px; }
  button { flex: 1; padding: 12px; border-radius: 8px; font-size: 16px; cursor: pointer; border: 1px solid #ddd; }
  .approve { background: #000; color: #fff; border: none; }
  .deny { background: #fff; }
</style></head><body>
<div class="card">
  <h1>Authorize MCP Client</h1>
  <p class="client">Client: <strong>${authReq.clientId}</strong></p>
  <p>This app wants access to:</p>
  <div class="scopes">${authReq.scope.map((s) => '<span class="scope">' + s + '</span>').join('')}</div>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="request_json" value='${JSON.stringify(authReq)}'>
    <div class="actions">
      <button type="submit" name="action" value="deny" class="deny">Deny</button>
      <button type="submit" name="action" value="approve" class="approve">Approve</button>
    </div>
  </form>
</div>
</body></html>`;
        return new Response(html, { headers: { 'Content-Type': 'text/html' } });
      }

      if (url.pathname === '/oauth/authorize' && request.method === 'POST') {
        const form = await request.formData();
        const action = form.get('action');
        const authReq = JSON.parse(form.get('request_json'));

        if (action === 'deny') {
          const redirectUrl = new URL(authReq.redirectUri);
          redirectUrl.searchParams.set('error', 'access_denied');
          if (authReq.state) redirectUrl.searchParams.set('state', authReq.state);
          return Response.redirect(redirectUrl.toString(), 302);
        }

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
  authorizeEndpoint: '/oauth/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
  scopesSupported: ['read', 'write', 'mcp'],
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400,
  storage: store,
});

export const provider = providerRef;
