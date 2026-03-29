'use client';
import { useState, useEffect } from 'react';

export default function Home() {
  const [state, setState] = useState('idle'); // idle | registering | ready | callback | done | error
  const [clientId, setClientId] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [userInfo, setUserInfo] = useState(null);
  const [error, setError] = useState(null);
  const [logs, setLogs] = useState([]);
  const [mcpSession, setMcpSession] = useState(null);
  const [mcpResult, setMcpResult] = useState(null);
  const [toolName, setToolName] = useState('hello');
  const [toolArgs, setToolArgs] = useState('{"name": "World"}');

  const log = (msg) => setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

  // PKCE helpers
  async function generatePKCE() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    return { verifier, challenge };
  }

  // 1. クライアント登録
  async function registerClient() {
    setState('registering');
    log('Registering client...');
    const res = await fetch('/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [window.location.origin + '/callback'],
        client_name: 'Playground App',
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      }),
    });
    const client = await res.json();
    setClientId(client.client_id);
    sessionStorage.setItem('client_id', client.client_id);
    log(`Client registered: ${client.client_id}`);
    setState('ready');
  }

  // 2. 認可開始
  async function startAuth() {
    const pkce = await generatePKCE();
    sessionStorage.setItem('pkce_verifier', pkce.verifier);
    const stateParam = crypto.randomUUID();
    sessionStorage.setItem('oauth_state', stateParam);

    const cid = clientId || sessionStorage.getItem('client_id');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: cid,
      redirect_uri: window.location.origin + '/callback',
      scope: 'read write',
      state: stateParam,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    });

    log('Redirecting to authorize...');
    window.location.href = `/oauth/authorize?${params}`;
  }

  // 3. コールバック処理
  async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const returnedState = params.get('state');
    const err = params.get('error');

    if (err) {
      setError(`Authorization denied: ${err}`);
      setState('error');
      return;
    }

    if (!code) return;

    setState('callback');
    log(`Authorization code received: ${code.slice(0, 16)}...`);

    const savedState = sessionStorage.getItem('oauth_state');
    if (returnedState !== savedState) {
      setError('State mismatch!');
      setState('error');
      return;
    }
    log('State verified');

    // トークン交換
    const verifier = sessionStorage.getItem('pkce_verifier');
    const cid = sessionStorage.getItem('client_id');
    log('Exchanging code for token...');

    const tokenRes = await fetch('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: window.location.origin + '/callback',
        client_id: cid,
        code_verifier: verifier,
      }),
    });
    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      setError(`Token error: ${tokenData.error_description || tokenData.error}`);
      setState('error');
      return;
    }

    setTokens(tokenData);
    log(`Access token: ${tokenData.access_token.slice(0, 16)}...`);
    log(`Token type: ${tokenData.token_type}, expires_in: ${tokenData.expires_in}`);

    // ユーザー情報取得
    log('Fetching /api/me...');
    const meRes = await fetch('/api/me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const meData = await meRes.json();
    setUserInfo(meData);
    log(`User: ${JSON.stringify(meData)}`);

    setState('done');
    window.history.replaceState({}, '', '/');
  }

  // 手動で /api/me を叩く
  async function callApi() {
    log('Fetching /api/me...');
    const res = await fetch('/api/me', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const data = await res.json();
    setUserInfo(data);
    log(`${res.status} ${JSON.stringify(data)}`);
  }

  // MCP セッション初期化
  async function mcpInit() {
    log('MCP: initializing...');
    const res = await fetch('/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        id: 1,
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'playground', version: '1.0.0' },
        },
      }),
    });

    const sessionId = res.headers.get('mcp-session-id');
    const text = await res.text();
    const data = text.includes('data: ') ? text.split('data: ').pop() : text;
    const result = JSON.parse(data);
    log(`MCP: connected — ${result.result.serverInfo.name} v${result.result.serverInfo.version}`);
    log(`MCP: tools available: ${result.result.capabilities.tools ? 'yes' : 'no'}`);
    setMcpSession(sessionId);

    // Send initialized notification
    await fetch('/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokens.access_token}`,
        'Mcp-Session-Id': sessionId,
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    });

    // List tools
    const toolsRes = await fetch('/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${tokens.access_token}`,
        'Mcp-Session-Id': sessionId,
      },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 2, params: {} }),
    });
    const toolsText = await toolsRes.text();
    const toolsData = JSON.parse(toolsText.includes('data: ') ? toolsText.split('data: ').pop() : toolsText);
    const toolNames = toolsData.result.tools.map((t) => `${t.name} — ${t.description}`);
    log(`MCP: tools: ${toolNames.join(', ')}`);
  }

  // MCP tool call
  async function mcpCall() {
    let args;
    try {
      args = JSON.parse(toolArgs);
    } catch {
      setError('Invalid JSON in tool arguments');
      return;
    }

    log(`MCP: calling ${toolName}(${JSON.stringify(args)})`);
    const res = await fetch('/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${tokens.access_token}`,
        'Mcp-Session-Id': mcpSession,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/call',
        id: Date.now(),
        params: { name: toolName, arguments: args },
      }),
    });

    const text = await res.text();
    const data = JSON.parse(text.includes('data: ') ? text.split('data: ').pop() : text);

    if (data.error) {
      log(`MCP: error — ${data.error.message}`);
      setMcpResult(data.error);
    } else {
      const content = data.result.content.map((c) => c.text).join('\n');
      log(`MCP: result — ${content}`);
      setMcpResult(data.result);
    }
  }

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('code') || params.has('error')) {
      handleCallback();
    } else {
      const savedClient = sessionStorage.getItem('client_id');
      if (savedClient) {
        setClientId(savedClient);
        setState('ready');
      }
    }
  }, []);

  return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 640, margin: '40px auto', padding: '0 20px' }}>
      <h1 style={{ fontSize: 24 }}>mcp-oauth Playground</h1>
      <p style={{ color: '#666' }}>OAuth 2.1 + PKCE flow demo</p>

      <div style={{ display: 'flex', gap: 12, margin: '24px 0', flexWrap: 'wrap' }}>
        {state === 'idle' && (
          <button onClick={registerClient} style={btnStyle}>
            1. Register Client
          </button>
        )}
        {(state === 'ready' || state === 'done') && (
          <button onClick={() => { sessionStorage.clear(); setClientId(null); setTokens(null); setUserInfo(null); setError(null); setLogs([]); setState('idle'); }} style={{ ...btnStyle, background: '#666' }}>
            Reset
          </button>
        )}
        {(state === 'ready' || state === 'done') && (
          <button onClick={startAuth} style={btnStyle}>
            {state === 'done' ? 'Re-authenticate' : '2. Login (OAuth)'}
          </button>
        )}
        {state === 'done' && tokens && (
          <button onClick={callApi} style={{ ...btnStyle, background: '#2563eb' }}>
            Call /api/me
          </button>
        )}
      </div>

      {clientId && (
        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 8px' }}>Client</h3>
          <code style={{ fontSize: 13 }}>{clientId}</code>
        </div>
      )}

      {tokens && (
        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 8px' }}>Tokens</h3>
          <pre style={{ fontSize: 12, overflow: 'auto' }}>
            {JSON.stringify(
              {
                access_token: tokens.access_token.slice(0, 24) + '...',
                token_type: tokens.token_type,
                expires_in: tokens.expires_in,
                refresh_token: tokens.refresh_token ? tokens.refresh_token.slice(0, 24) + '...' : undefined,
                scope: tokens.scope,
              },
              null,
              2,
            )}
          </pre>
        </div>
      )}

      {userInfo && (
        <div style={{ ...cardStyle, background: '#f0fdf4', borderColor: '#bbf7d0' }}>
          <h3 style={{ margin: '0 0 8px' }}>User Info (GET /api/me)</h3>
          <pre style={{ fontSize: 13 }}>{JSON.stringify(userInfo, null, 2)}</pre>
        </div>
      )}

      {state === 'done' && tokens && (
        <div style={{ ...cardStyle, background: '#f5f3ff', borderColor: '#c4b5fd' }}>
          <h3 style={{ margin: '0 0 12px' }}>MCP Tools</h3>
          {!mcpSession ? (
            <button onClick={mcpInit} style={{ ...btnStyle, background: '#7c3aed' }}>
              Connect to MCP Server
            </button>
          ) : (
            <div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <select
                  value={toolName}
                  onChange={(e) => {
                    setToolName(e.target.value);
                    setToolArgs(e.target.value === 'hello' ? '{"name": "World"}' : '{}');
                  }}
                  style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd', fontSize: 14 }}
                >
                  <option value="hello">hello</option>
                  <option value="whoami">whoami</option>
                </select>
                <input
                  value={toolArgs}
                  onChange={(e) => setToolArgs(e.target.value)}
                  style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd', fontSize: 14, fontFamily: 'monospace' }}
                />
                <button onClick={mcpCall} style={{ ...btnStyle, background: '#7c3aed', padding: '8px 16px' }}>
                  Call
                </button>
              </div>
              {mcpResult && (
                <pre style={{ fontSize: 12, background: '#fff', padding: 12, borderRadius: 6, overflow: 'auto', margin: 0 }}>
                  {JSON.stringify(mcpResult, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}

      {error && (
        <div style={{ ...cardStyle, background: '#fef2f2', borderColor: '#fecaca' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {logs.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h3 style={{ fontSize: 14, color: '#666' }}>Log</h3>
          <div
            style={{
              background: '#1a1a1a',
              color: '#0f0',
              padding: 16,
              borderRadius: 8,
              fontSize: 12,
              fontFamily: 'monospace',
              maxHeight: 300,
              overflow: 'auto',
            }}
          >
            {logs.map((l, i) => (
              <div key={i}>{l}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const btnStyle = {
  padding: '12px 24px',
  fontSize: 16,
  borderRadius: 8,
  border: 'none',
  background: '#000',
  color: '#fff',
  cursor: 'pointer',
};

const cardStyle = {
  border: '1px solid #ddd',
  borderRadius: 8,
  padding: 16,
  marginBottom: 12,
};
