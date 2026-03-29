import http from 'node:http';
import { Readable } from 'node:stream';
import { OAuthProvider, MemoryStore } from './lib/mcp-oauth.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod/v4';

const PORT = 9876;

// --- MCP Server ---
function createMcpServer() {
  const server = new McpServer({ name: 'hello-mcp', version: '1.0.0' });

  server.tool('hello', 'Say hello to someone', { name: z.string() }, async ({ name }) => ({
    content: [{ type: 'text', text: `Hello, ${name}!` }],
  }));

  server.tool('whoami', 'Show current user info', {}, async (_args, extra) => ({
    content: [
      {
        type: 'text',
        text: JSON.stringify(extra.authInfo, null, 2),
      },
    ],
  }));

  return server;
}

// Session management
const transports = new Map();

// --- OAuth Provider ---
const store = new MemoryStore();
let provider;
provider = new OAuthProvider({
  apiRoute: '/mcp',
  apiHandler: {
    async fetch(request, ctx) {
      // MCP requests arrive here already authenticated
      // ctx.props has user info from the Grant

      const sessionId = request.headers.get('mcp-session-id');
      let transport;

      if (sessionId && transports.has(sessionId)) {
        transport = transports.get(sessionId);
      } else if (request.method === 'POST' || request.method === 'GET') {
        transport = new WebStandardStreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (sid) => transports.set(sid, transport),
          onsessionclosed: (sid) => transports.delete(sid),
        });
        const mcpServer = createMcpServer();
        await mcpServer.connect(transport);
      } else {
        return new Response('Method not allowed', { status: 405 });
      }

      return transport.handleRequest(request, {
        authInfo: { userId: ctx.props?.name ?? 'unknown', ...ctx.props },
      });
    },
  },
  defaultHandler: {
    async fetch(request) {
      const url = new URL(request.url);

      if (url.pathname === '/authorize' && request.method === 'GET') {
        const authReq = await provider.parseAuthRequest(request);
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
  <form method="POST" action="/authorize">
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

      if (url.pathname === '/authorize' && request.method === 'POST') {
        const form = await request.formData();
        const action = form.get('action');
        const authReq = JSON.parse(form.get('request_json'));

        if (action === 'deny') {
          const redirectUrl = new URL(authReq.redirectUri);
          redirectUrl.searchParams.set('error', 'access_denied');
          if (authReq.state) redirectUrl.searchParams.set('state', authReq.state);
          return Response.redirect(redirectUrl.toString(), 302);
        }

        const { redirectTo } = await provider.completeAuthorization({
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
  scopesSupported: ['mcp'],
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400,
  storage: store,
});

// --- Node.js HTTP helpers ---
function toWebRequest(nodeReq) {
  const url = `http://${nodeReq.headers.host}${nodeReq.url}`;
  const headers = new Headers();
  for (const [key, val] of Object.entries(nodeReq.headers)) {
    if (val) headers.set(key, Array.isArray(val) ? val.join(', ') : val);
  }
  const init = { method: nodeReq.method, headers };
  if (nodeReq.method !== 'GET' && nodeReq.method !== 'HEAD') {
    init.body = Readable.toWeb(nodeReq);
    init.duplex = 'half';
  }
  return new Request(url, init);
}

async function writeWebResponse(webRes, nodeRes) {
  nodeRes.writeHead(webRes.status, Object.fromEntries(webRes.headers));
  if (webRes.body) {
    const reader = webRes.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        nodeRes.write(value);
      }
    } finally {
      nodeRes.end();
    }
  } else {
    nodeRes.end();
  }
}

// --- HTTP Server ---
const server = http.createServer(async (nodeReq, nodeRes) => {
  try {
    const webReq = toWebRequest(nodeReq);
    const webRes = await provider.fetch(webReq);
    await writeWebResponse(webRes, nodeRes);
  } catch (err) {
    console.error(err);
    if (!nodeRes.headersSent) {
      nodeRes.writeHead(500);
      nodeRes.end('Internal Server Error');
    }
  }
});

server.listen(PORT, () => {
  console.log(`\n  MCP OAuth Server running at http://localhost:${PORT}`);
  console.log(`  MCP endpoint:    http://localhost:${PORT}/mcp`);
  console.log(`  OAuth metadata:  http://localhost:${PORT}/.well-known/oauth-authorization-server`);
  console.log(`\n  Test with MCP Inspector:`);
  console.log(`    npx @modelcontextprotocol/inspector --url http://localhost:${PORT}/mcp\n`);
});
