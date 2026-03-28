import {
  OAuthProvider,
  type TokenSummary,
  type ResolveExternalTokenInput,
  type ResolveExternalTokenResult,
} from './oauth-provider';

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
 *
 * Usage in `app/[...oauth]/route.ts`:
 * ```typescript
 * export const { GET, POST, OPTIONS, DELETE, PUT, PATCH } = createOAuthHandlers(provider);
 * ```
 */
export function createOAuthHandlers(provider: OAuthProvider): OAuthRouteHandlers {
  const handler: RouteHandler = (request) => provider.fetch(request);
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
 * Successful authentication with an internal token (managed by OAuthProvider)
 */
export interface AuthResult<T = any> {
  authenticated: true;
  external?: false;
  token: TokenSummary<T>;
}

/**
 * Successful authentication with an external token (resolved via callback)
 */
export interface ExternalAuthResult<T = any> {
  authenticated: true;
  external: true;
  props: T;
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
   *
   * This should be the same `resolveExternalToken` passed to `OAuthProviderOptions`.
   * It is required here because `OAuthProvider` does not expose its internal options,
   * and `getAuth` cannot access them without modifying the upstream core.
   */
  resolveExternalToken?: (input: ResolveExternalTokenInput) => Promise<ResolveExternalTokenResult | null>;
}

/**
 * Extract and verify the Bearer token from a request.
 *
 * Validates the token via `unwrapToken`, checks audience constraints against the
 * request URL, and optionally falls back to an external token resolver.
 *
 * Without options: returns `AuthResult | AuthFailure` (backwards compatible).
 * With `resolveExternalToken`: may also return `ExternalAuthResult`.
 *
 * Note: `unwrapToken` returns null for both missing and expired internal tokens.
 * When `resolveExternalToken` is configured, expired internal tokens may reach
 * the external resolver. In practice this is safe because external resolvers
 * validate their own token format and will not re-authenticate an internal token.
 *
 * Usage:
 * ```typescript
 * // Internal tokens only (backwards compatible)
 * const auth = await getAuth(provider, request);
 * if (!auth.authenticated) return auth.error;
 * auth.token.grant.props // TokenSummary
 *
 * // With external token support
 * const auth = await getAuth(provider, request, { resolveExternalToken });
 * if (!auth.authenticated) return auth.error;
 * if (auth.external) { auth.props } else { auth.token }
 * ```
 */
export function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request
): Promise<AuthResult<T> | AuthFailure>;
export function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request,
  options?: GetAuthOptions
): Promise<AuthResult<T> | ExternalAuthResult<T> | AuthFailure>;
export async function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request,
  options?: GetAuthOptions
): Promise<AuthResult<T> | ExternalAuthResult<T> | AuthFailure> {
  const authHeader = request.headers.get('Authorization');

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
    if (!validateAudience(tokenSummary.audience, request)) {
      return audienceMismatchResponse();
    }
    return { authenticated: true, external: false, token: tokenSummary };
  }

  // Fall back to external token resolution.
  // This mirrors OAuthProvider.fetch(), which tries resolveExternalToken when the
  // internal token lookup fails, regardless of the token's format.
  if (options?.resolveExternalToken) {
    const ext = await options.resolveExternalToken({ token: rawToken, request });
    if (ext) {
      if (!validateAudience(ext.audience, request)) {
        return audienceMismatchResponse();
      }
      return { authenticated: true, external: true, props: ext.props as T, audience: ext.audience };
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
