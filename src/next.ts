import { OAuthProvider, type TokenSummary, type ResolveExternalTokenInput } from './oauth-provider';

/**
 * Next.js App Router route handler signature
 */
type RouteHandler = (request: Request) => Promise<Response>;

/**
 * All HTTP method handlers for a Next.js catch-all route
 */
export interface OAuthRouteHandlers {
  GET: RouteHandler;
  POST: RouteHandler;
  OPTIONS: RouteHandler;
  DELETE: RouteHandler;
  PUT: RouteHandler;
  PATCH: RouteHandler;
}

/**
 * Create Next.js App Router route handlers that delegate to an OAuthProvider.
 * Reconstructs the public request URL from forwarded headers when Next standalone
 * provides an internal container hostname in `request.url`.
 *
 * Usage in `app/[...oauth]/route.ts`:
 * ```typescript
 * export const { GET, POST, OPTIONS, DELETE, PUT, PATCH } = createOAuthHandlers(provider);
 * ```
 */
export function createOAuthHandlers(provider: OAuthProvider): OAuthRouteHandlers {
  const handler: RouteHandler = (request) => provider.fetch(normalizeNextRequest(request));
  return {
    GET: handler,
    POST: handler,
    OPTIONS: handler,
    DELETE: handler,
    PUT: handler,
    PATCH: handler,
  };
}

/**
 * Successful authentication result.
 * For external tokens, metadata fields other than `grant.props` and `audience`
 * may contain placeholder values.
 */
export interface AuthResult<T = any> {
  authenticated: true;
  token: TokenSummary<T>;
  external?: true;
  audience?: string | string[];
}

/**
 * Failed authentication result
 */
export interface AuthFailure {
  authenticated: false;
  error: Response;
}

/**
 * Options for getAuth
 */
export interface GetAuthOptions {
  /**
   * Optional callback to resolve external (non-internal) Bearer tokens.
   * Called when `unwrapToken` returns null.
   */
  resolveExternalToken?: NonNullable<ReturnType<OAuthProvider['getResolveExternalToken']>>;
}

/**
 * Extract and verify the Bearer token from a request.
 *
 * Validates the token via `unwrapToken`, checks audience constraints against the
 * request URL, and falls back to an external token resolver if configured.
 *
 * The external resolver is looked up in this order:
 * 1. `options.resolveExternalToken` (explicit per-call override)
 * 2. `provider`'s configured `resolveExternalToken`
 *
 * Note: `unwrapToken` returns null for both missing and expired internal tokens.
 * When `resolveExternalToken` is configured, expired internal tokens may reach
 * the external resolver. In practice this is safe because external resolvers
 * validate their own token format and will not re-authenticate an internal token.
 *
 * For Next standalone deployments, `getAuth()` also normalizes internal
 * container hostnames in `request.url` using forwarded headers before doing
 * audience validation or invoking an external token resolver.
 *
 * Usage:
 * ```typescript
 * const provider = new OAuthProvider({ ...options, resolveExternalToken });
 * const auth = await getAuth(provider, request);
 *
 * // Or pass resolveExternalToken explicitly per call
 * const auth = await getAuth(provider, request, { resolveExternalToken });
 *
 * if (!auth.authenticated) return auth.error;
 * auth.token.grant.props // Always available
 * ```
 */
export function getAuth<T = any>(provider: OAuthProvider, request: Request): Promise<AuthResult<T> | AuthFailure>;
export function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request,
  options: GetAuthOptions
): Promise<AuthResult<T> | AuthFailure>;
export async function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request,
  options?: GetAuthOptions
): Promise<AuthResult<T> | AuthFailure> {
  const normalizedRequest = normalizeNextRequest(request);
  const authHeader = normalizedRequest.headers.get('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authenticated: false,
      error: new Response(JSON.stringify({ error: 'invalid_token', error_description: 'Missing Bearer token' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer',
        },
      }),
    };
  }

  const rawToken = authHeader.slice(7);

  // Try internal token first
  const tokenSummary = await provider.unwrapToken<T>(rawToken);

  if (tokenSummary) {
    if (!validateAudience(tokenSummary.audience, normalizedRequest)) {
      return audienceMismatchResponse();
    }
    return { authenticated: true, token: tokenSummary };
  }

  // Fall back to external token resolution.
  // Explicit options take precedence; otherwise use the resolver configured on the provider.
  const resolver = options?.resolveExternalToken ?? provider.getResolveExternalToken();
  if (resolver) {
    const ext = await resolver({ token: rawToken, request: normalizedRequest });
    if (ext) {
      if (!validateAudience(ext.audience, normalizedRequest)) {
        return audienceMismatchResponse();
      }
      return {
        authenticated: true,
        external: true,
        audience: ext.audience,
        token: {
          id: '',
          grantId: '',
          userId: '',
          createdAt: 0,
          expiresAt: 0,
          audience: ext.audience,
          scope: [],
          grant: {
            clientId: '',
            scope: [],
            props: ext.props as T,
          },
        },
      };
    }
  }

  return {
    authenticated: false,
    error: new Response(JSON.stringify({ error: 'invalid_token', error_description: 'Invalid or expired token' }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      },
    }),
  };
}

function normalizeNextRequest(request: Request): Request {
  const publicUrl = derivePublicRequestUrl(request);
  if (!publicUrl || publicUrl === request.url) {
    return request;
  }

  return new Request(publicUrl, request);
}

function derivePublicRequestUrl(request: Request): string | null {
  const requestUrl = new URL(request.url);
  const forwarded = parseForwardedHeader(request.headers.get('forwarded'));
  const host = firstHeaderValue(
    forwarded.host ?? request.headers.get('x-forwarded-host') ?? request.headers.get('host')
  );

  if (!host) {
    return null;
  }

  const protocol = resolveProtocol(
    forwarded.proto ?? firstHeaderValue(request.headers.get('x-forwarded-proto')),
    requestUrl
  );
  const authority = applyForwardedPort(host, protocol, firstHeaderValue(request.headers.get('x-forwarded-port')));

  return `${protocol}://${authority}${requestUrl.pathname}${requestUrl.search}${requestUrl.hash}`;
}

function parseForwardedHeader(value: string | null): { host?: string; proto?: string } {
  if (!value) {
    return {};
  }

  const firstEntry = value.split(',')[0];
  const result: { host?: string; proto?: string } = {};

  for (const part of firstEntry.split(';')) {
    const [rawKey, rawValue] = part.split('=', 2);
    if (!rawKey || !rawValue) {
      continue;
    }

    const key = rawKey.trim().toLowerCase();
    const parsedValue = unquoteHeaderValue(rawValue.trim());

    if (key === 'host') {
      result.host = parsedValue;
    } else if (key === 'proto') {
      result.proto = parsedValue;
    }
  }

  return result;
}

function firstHeaderValue(value: string | null | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  const firstValue = value.split(',')[0]?.trim();
  return firstValue ? unquoteHeaderValue(firstValue) : undefined;
}

function unquoteHeaderValue(value: string): string {
  return value.replace(/^"(.*)"$/, '$1');
}

function resolveProtocol(forwardedProto: string | undefined, requestUrl: URL): 'http' | 'https' {
  const fallback = requestUrl.protocol === 'https:' ? 'https' : 'http';
  if (!forwardedProto) {
    return fallback;
  }

  const normalized = forwardedProto.toLowerCase();
  return normalized === 'https' || normalized === 'http' ? normalized : fallback;
}

function applyForwardedPort(host: string, protocol: 'http' | 'https', forwardedPort: string | undefined): string {
  if (!forwardedPort || hostHasExplicitPort(host) || isDefaultPort(protocol, forwardedPort)) {
    return host;
  }

  return `${host}:${forwardedPort}`;
}

function hostHasExplicitPort(host: string): boolean {
  if (host.startsWith('[')) {
    return host.includes(']:');
  }

  return host.includes(':');
}

function isDefaultPort(protocol: 'http' | 'https', port: string): boolean {
  return (protocol === 'https' && port === '443') || (protocol === 'http' && port === '80');
}

/**
 * Validate audience constraint against a request URL.
 * Returns true if no audience is set or it matches.
 */
function validateAudience(audience: string | string[] | undefined, request: Request): boolean {
  if (!audience) return true;
  const requestUrl = new URL(request.url);
  const resourceServer = `${requestUrl.protocol}//${requestUrl.host}${requestUrl.pathname}`;
  const audiences = Array.isArray(audience) ? audience : [audience];
  return audiences.some((aud) => audienceMatches(resourceServer, aud));
}

function audienceMismatchResponse(): AuthFailure {
  return {
    authenticated: false,
    error: new Response(
      JSON.stringify({ error: 'invalid_token', error_description: 'Token audience does not match resource' }),
      {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer error="invalid_token"',
        },
      }
    ),
  };
}

/**
 * Check whether a resource server URL matches an audience value.
 * Mirrors the audience matching logic in OAuthProvider.fetch().
 */
function audienceMatches(resourceServerUrl: string, audienceValue: string): boolean {
  try {
    const resource = new URL(resourceServerUrl);
    const audience = new URL(audienceValue);

    if (resource.origin !== audience.origin) {
      return false;
    }

    if (audience.pathname === '/' || audience.pathname === '') {
      return true;
    }

    return resource.pathname === audience.pathname || resource.pathname.startsWith(audience.pathname + '/');
  } catch {
    return false;
  }
}

// Re-export all public types from core
export {
  OAuthProvider,
  MemoryStore,
  GrantType,
  type StorageAdapter,
  type OAuthContext,
  type ApiHandler,
  type DefaultHandler,
  type TokenExchangeCallbackResult,
  type TokenExchangeCallbackOptions,
  type ResolveExternalTokenInput,
  type ResolveExternalTokenResult,
  type OAuthProviderOptions,
  type OAuthHelpers,
  type ExchangeTokenOptions,
  type AuthRequest,
  type ClientInfo,
  type CompleteAuthorizationOptions,
  type Grant,
  type TokenBase,
  type Token,
  type TokenSummary,
  type ListOptions,
  type ListResult,
  type GrantSummary,
} from './oauth-provider';
