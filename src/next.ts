import { OAuthProvider, type TokenSummary } from './oauth-provider';

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
 * Successful authentication result
 */
export interface AuthResult<T = any> {
  authenticated: true;
  token: TokenSummary<T>;
}

/**
 * Failed authentication result
 */
export interface AuthFailure {
  authenticated: false;
  error: Response;
}

/**
 * Extract and verify the Bearer token from a request.
 *
 * Returns `{ authenticated: true, token }` with the decrypted token data on success,
 * or `{ authenticated: false, error }` with a 401 Response on failure.
 *
 * Usage in a standalone API route:
 * ```typescript
 * export async function GET(request: Request) {
 *   const auth = await getAuth(provider, request);
 *   if (!auth.authenticated) return auth.error;
 *   // auth.token.props contains the user data
 * }
 * ```
 */
export async function getAuth<T = any>(
  provider: OAuthProvider,
  request: Request
): Promise<AuthResult<T> | AuthFailure> {
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

  const token = authHeader.slice(7);
  const tokenSummary = await provider.unwrapToken<T>(token);

  if (!tokenSummary) {
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

  return {
    authenticated: true,
    token: tokenSummary,
  };
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
