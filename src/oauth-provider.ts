// Storage Adapter

/**
 * Abstract storage interface replacing Cloudflare KV.
 * Implementations must support prefix-based listing and TTL-based expiration.
 */
export interface StorageAdapter {
  /**
   * Get a value by key. Returns null if not found or expired.
   */
  get(key: string): Promise<string | null>;

  /**
   * Store a value with optional TTL-based expiration.
   * @param key - The storage key
   * @param value - The string value to store
   * @param options - Optional expiration settings
   */
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;

  /**
   * Delete a key.
   */
  delete(key: string): Promise<void>;

  /**
   * List keys matching a prefix with cursor-based pagination.
   */
  list(options: {
    prefix: string;
    limit?: number;
    cursor?: string;
  }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }>;
}

/**
 * In-memory StorageAdapter for development and testing.
 * Not suitable for production use.
 */
export class MemoryStore implements StorageAdapter {
  private data = new Map<string, { value: string; expiration?: number }>();

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiration && entry.expiration <= Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiration = options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : undefined;
    this.data.set(key, { value, expiration });
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  async list(options: {
    prefix: string;
    limit?: number;
    cursor?: string;
  }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }> {
    const now = Date.now();
    const allKeys = Array.from(this.data.keys())
      .filter((key) => {
        if (!key.startsWith(options.prefix)) return false;
        const entry = this.data.get(key)!;
        if (entry.expiration && entry.expiration <= now) {
          this.data.delete(key);
          return false;
        }
        return true;
      })
      .sort();

    const limit = options.limit ?? 1000;
    let startIndex = 0;

    if (options.cursor) {
      const cursorIndex = allKeys.indexOf(options.cursor);
      if (cursorIndex !== -1) {
        startIndex = cursorIndex + 1;
      }
    }

    const keys = allKeys.slice(startIndex, startIndex + limit);
    const hasMore = startIndex + limit < allKeys.length;

    return {
      keys: keys.map((name) => ({ name })),
      list_complete: !hasMore,
      cursor: hasMore ? keys[keys.length - 1] : undefined,
    };
  }

  /**
   * Clear all data. Useful for test cleanup.
   */
  clear(): void {
    this.data.clear();
  }
}

// Types

/**
 * Enum representing OAuth grant types
 */
export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  REFRESH_TOKEN = 'refresh_token',
  TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange',
}

/**
 * Context passed to API handlers with authenticated request properties.
 */
export interface OAuthContext {
  /** Decrypted application-specific properties from the access token */
  props: any;
}

/**
 * Handler for API requests that have been authenticated with a valid access token.
 */
export interface ApiHandler {
  fetch(request: Request, ctx: OAuthContext): Promise<Response>;
}

/**
 * Handler for non-API requests (authorization pages, etc.)
 */
export interface DefaultHandler {
  fetch(request: Request): Promise<Response>;
}

/**
 * Configuration options for the OAuth Provider
 */
/**
 * Result of a token exchange callback function.
 * Allows updating the props stored in both the access token and the grant.
 */
export interface TokenExchangeCallbackResult {
  /**
   * New props to be stored specifically with the access token.
   * If not provided but newProps is, the access token will use newProps.
   * If neither is provided, the original props will be used.
   */
  accessTokenProps?: any;

  /**
   * New props to replace the props stored in the grant itself.
   * These props will be used for all future token refreshes.
   * If accessTokenProps is not provided, these props will also be used for the current access token.
   * If not provided, the original props will be used.
   */
  newProps?: any;

  /**
   * Override the default access token TTL (time-to-live) for this specific token.
   * This is especially useful when the application is also an OAuth client to another service
   * and wants to match its access token TTL to the upstream access token TTL.
   * Value should be in seconds.
   */
  accessTokenTTL?: number;

  /**
   * Override the default refresh token TTL (time-to-live) for this specific grant.
   * Value should be in seconds.
   * Note: This is only honored during authorization code exchange. If returned during
   * refresh token exchange, it will be ignored.
   */
  refreshTokenTTL?: number;

  /**
   * List of scopes authorized for the new access token
   * (If undefined, the granted scopes will be used)
   */
  accessTokenScope?: string[];
}

/**
 * Options for token exchange callback functions
 */
export interface TokenExchangeCallbackOptions {
  /**
   * The type of grant being processed.
   */
  grantType: GrantType;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * List of scopes that were requested for this token by the client
   * (Will be the same as granted scopes unless client specifically requested a downscoping)
   */
  requestedScope: string[];

  /**
   * Application-specific properties currently associated with this grant
   */
  props: any;

  /**
   * The actor token, if present in the request (RFC 8693 Section 2.1).
   * Represents the party acting on behalf of the subject.
   */
  actorToken?: string;

  /**
   * The actor token type URI, if actor_token was provided.
   */
  actorTokenType?: string;

  /**
   * Resolved actor token information, if actor_token was a valid internal access token.
   * Contains the decrypted props and claims from the actor's token.
   */
  actorTokenInfo?: TokenSummary;
}

/**
 * Input parameters for the resolveExternalToken callback function
 */
export interface ResolveExternalTokenInput {
  /**
   * The token string that was provided in the Authorization header
   */
  token: string;

  /**
   * The original HTTP request
   */
  request: Request;
}

/**
 * Result returned from the resolveExternalToken callback function
 */
export interface ResolveExternalTokenResult {
  /**
   * Application-specific properties that will be passed to the API handlers
   * These properties are set in the execution context (ctx.props) when the external token is validated
   */
  props: any;

  /**
   * Audience claim from the external token (RFC 7519 Section 4.1.3)
   * If provided, will be validated against the resource server identity
   *
   */
  audience?: string | string[];
}

export interface OAuthProviderOptions {
  /**
   * Storage adapter for persisting OAuth data (clients, grants, tokens).
   */
  storage: StorageAdapter;

  /**
   * URL(s) for API routes. Requests with URLs starting with any of these prefixes
   * will be treated as API requests and require a valid access token.
   * Can be a single route or an array of routes. Each route can be a full URL or just a path.
   *
   * Used with `apiHandler` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiRoute?: string | string[];

  /**
   * Handler for API requests that have a valid access token.
   * This handler will receive the authenticated user properties in ctx.props.
   *
   * Used with `apiRoute` for the single-handler configuration. This is incompatible with
   * the `apiHandlers` property. You must use either `apiRoute` + `apiHandler` OR `apiHandlers`, not both.
   */
  apiHandler?: ApiHandler;

  /**
   * Map of API routes to their corresponding handlers for the multi-handler configuration.
   * The keys are the API routes (strings only, not arrays), and the values are the handlers.
   * Each route can be a full URL or just a path.
   *
   * This is incompatible with the `apiRoute` and `apiHandler` properties. You must use either
   * `apiRoute` + `apiHandler` (single-handler configuration) OR `apiHandlers` (multi-handler
   * configuration), not both.
   */
  apiHandlers?: Record<string, ApiHandler>;

  /**
   * Handler for all non-API requests or API requests without a valid token.
   */
  defaultHandler: DefaultHandler;

  /**
   * URL of the OAuth authorization endpoint where users can grant permissions.
   * This URL is used in OAuth metadata and is not handled by the provider itself.
   */
  authorizeEndpoint: string;

  /**
   * URL of the token endpoint which the provider will implement.
   * This endpoint handles token issuance, refresh, and revocation.
   */
  tokenEndpoint: string;

  /**
   * Optional URL for the client registration endpoint.
   * If provided, the provider will implement dynamic client registration.
   */
  clientRegistrationEndpoint?: string;

  /**
   * Time-to-live for access tokens in seconds.
   * Defaults to 1 hour (3600 seconds) if not specified.
   */
  accessTokenTTL?: number;

  /**
   * Time-to-live for refresh tokens in seconds.
   * Defaults to 0 (refresh tokens disabled).
   * Set to a positive number to enable refresh tokens with expiration,
   * or undefined for refresh tokens that do not expire.
   */
  refreshTokenTTL?: number;

  /**
   * Grace period in seconds during which the previous refresh token
   * remains valid after rotation. Only applies when refresh token rotation is active.
   * After this period, only the current refresh token is accepted.
   * Defaults to undefined (previous token valid until new token is first used).
   * Set to 0 to immediately invalidate the previous token on rotation.
   */
  refreshTokenGracePeriod?: number;

  /**
   * When true, if a previously-rotated refresh token is reused after being fully
   * superseded (replay detected), the entire grant is revoked as a security measure.
   * Defaults to false.
   */
  revokeGrantOnRefreshTokenReplay?: boolean;

  /**
   * List of scopes supported by this OAuth provider.
   * If not provided, the 'scopes_supported' field will be omitted from the OAuth metadata.
   */
  scopesSupported?: string[];

  /**
   * Controls whether the OAuth implicit flow is allowed.
   * This flow is discouraged in OAuth 2.1 due to security concerns.
   * Defaults to false.
   */
  allowImplicitFlow?: boolean;

  /**
   * Controls whether the plain PKCE method is allowed.
   * OAuth 2.1 recommends using S256 exclusively as plain offers no cryptographic protection.
   * When set to false, only the S256 code_challenge_method will be accepted.
   * Defaults to false.
   */
  allowPlainPKCE?: boolean;

  /**
   * Controls whether OAuth 2.0 Token Exchange (RFC 8693) is allowed.
   * When false, the token exchange grant type will not be advertised in metadata
   * and token exchange requests will be rejected.
   * Defaults to false.
   */
  allowTokenExchangeGrant?: boolean;

  /**
   * Controls whether public clients (clients without a secret, like SPAs) can register via the
   * dynamic client registration endpoint. When true, only confidential clients can register.
   * Note: Creating public clients via the OAuthHelpers.createClient() method is always allowed.
   * Defaults to false.
   */
  disallowPublicClientRegistration?: boolean;

  /**
   * Optional callback function that is called during token exchange.
   * This allows updating the props stored in both the access token and the grant.
   * For example, if the application itself is also a client to some other OAuth API,
   * it may want to perform the equivalent upstream token exchange, and store the result in the props.
   *
   * The callback can return new props values that will be stored with the token or grant.
   * If the callback returns nothing or undefined for a props field, the original props will be used.
   */
  tokenExchangeCallback?: (
    options: TokenExchangeCallbackOptions
  ) => Promise<TokenExchangeCallbackResult | void> | TokenExchangeCallbackResult | void;

  /**
   * Optional callback function that is called when a provided token was not found in the internal storage.
   * This allows authentication through external OAuth servers.
   * For example, if a request includes an authenticated token from a different OAuth authentication server,
   * the callback can be used to authenticate it and set the context props through it.
   *
   * The callback can optionally return props values that will passed-through to the apiHandlers.
   * The callback can return `null` to signal resolution failure.
   */
  resolveExternalToken?: (input: ResolveExternalTokenInput) => Promise<ResolveExternalTokenResult | null>;

  /**
   * Optional callback function that is called whenever the OAuthProvider returns an error response
   * This allows the client to emit notifications or perform other actions when an error occurs.
   *
   * If the function returns a Response, that will be used in place of the OAuthProvider's default one.
   */
  onError?: (error: {
    code: string;
    description: string;
    status: number;
    headers: Record<string, string>;
  }) => Response | void;

  /**
   * Explicitly enable Client ID Metadata Document (CIMD) support.
   * When true, URL-formatted client_ids will be fetched as metadata documents.
   * Defaults to false.
   */
  clientIdMetadataDocumentEnabled?: boolean;

  /**
   * TTL in seconds for caching fetched Client ID Metadata Documents in the StorageAdapter.
   * When set to a positive number, CIMD responses are cached to avoid repeated HTTP fetches.
   * On fetch failure, a stale cached entry will be served if available.
   * Set to 0 or leave undefined to disable caching (current behavior).
   * Defaults to 0.
   */
  cimdCacheTtl?: number;

  /**
   * Optional metadata for RFC 9728 OAuth 2.0 Protected Resource Metadata.
   * Controls the response served at /.well-known/oauth-protected-resource.
   *
   * If not provided, the endpoint will be automatically generated using the request origin
   * as the resource identifier, and the token endpoint's origin as the authorization server.
   */
  resourceMetadata?: {
    /**
     * The protected resource identifier URL (RFC 9728 `resource` field).
     * If not set, defaults to the request URL's origin.
     */
    resource?: string;
    /**
     * List of authorization server issuer URLs that can issue tokens for this resource.
     * If not set, defaults to the token endpoint's origin (consistent with the issuer
     * in authorization server metadata).
     */
    authorization_servers?: string[];
    /**
     * Scopes supported by this protected resource.
     * If not set, falls back to the top-level scopesSupported option.
     */
    scopes_supported?: string[];
    /**
     * Methods by which bearer tokens can be presented to this resource.
     * Defaults to ["header"].
     */
    bearer_methods_supported?: string[];
    /**
     * Human-readable name for this resource.
     */
    resource_name?: string;
  };
}

/**
 * Helper methods for OAuth operations
 */
export interface OAuthHelpers {
  /**
   * Parses an OAuth authorization request from the HTTP request
   * @param request - The HTTP request containing OAuth parameters
   * @returns The parsed authorization request parameters
   */
  parseAuthRequest(request: Request): Promise<AuthRequest>;

  /**
   * Looks up a client by its client ID
   * @param clientId - The client ID to look up
   * @returns A Promise resolving to the client info, or null if not found
   */
  lookupClient(clientId: string): Promise<ClientInfo | null>;

  /**
   * Completes an authorization request by creating a grant and authorization code
   * @param options - Options specifying the grant details
   * @returns A Promise resolving to an object containing the redirect URL
   */
  completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }>;

  /**
   * Creates a new OAuth client
   * @param clientInfo - Partial client information to create the client with
   * @returns A Promise resolving to the created client info
   */
  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo>;

  /**
   * Lists all registered OAuth clients with pagination support
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with items and optional cursor
   */
  listClients(options?: ListOptions): Promise<ListResult<ClientInfo>>;

  /**
   * Updates an existing OAuth client
   * @param clientId - The ID of the client to update
   * @param updates - Partial client information with fields to update
   * @returns A Promise resolving to the updated client info, or null if not found
   */
  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null>;

  /**
   * Deletes an OAuth client
   * @param clientId - The ID of the client to delete
   * @returns A Promise resolving when the deletion is confirmed.
   */
  deleteClient(clientId: string): Promise<void>;

  /**
   * Lists all authorization grants for a specific user with pagination support
   * Returns a summary of each grant without sensitive information
   * @param userId - The ID of the user whose grants to list
   * @param options - Optional pagination parameters (limit and cursor)
   * @returns A Promise resolving to the list result with grant summaries and optional cursor
   */
  listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>>;

  /**
   * Revokes an authorization grant
   * @param grantId - The ID of the grant to revoke
   * @param userId - The ID of the user who owns the grant
   * @returns A Promise resolving when the revocation is confirmed.
   */
  revokeGrant(grantId: string, userId: string): Promise<void>;

  /**
   * Decodes a token and returns token data with decrypted props
   * @param token - The token
   * @returns Promise resolving to token data with decrypted props, or null if token is invalid
   */
  unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null>;

  /**
   * Exchanges an existing access token for a new one with modified characteristics
   * Implements OAuth 2.0 Token Exchange (RFC 8693)
   * @param options - Options for token exchange including subject token and optional modifications
   * @returns Promise resolving to token response with new access token
   */
  exchangeToken(options: ExchangeTokenOptions): Promise<TokenResponse>;
}

/**
 * Options for token exchange operations (RFC 8693)
 */
export interface ExchangeTokenOptions {
  /**
   * The subject token to exchange (existing access token)
   */
  subjectToken: string;

  /**
   * Optional narrowed set of scopes for the new token (must be subset of original grant scopes)
   */
  scope?: string[];

  /**
   * Optional target audience/resource for the new token (maps to resource parameter per RFC 8707)
   */
  aud?: string | string[];

  /**
   * Optional TTL override for the new token in seconds (must not exceed subject token's remaining lifetime)
   */
  expiresIn?: number;

  /**
   * The actor token for delegation/impersonation scenarios (RFC 8693 Section 2.1)
   */
  actorToken?: string;

  /**
   * The actor token type URI. Required if actorToken is provided.
   * Defaults to 'urn:ietf:params:oauth:token-type:access_token'.
   */
  actorTokenType?: string;
}

/**
 * Parsed OAuth authorization request parameters
 */
export interface AuthRequest {
  /**
   * OAuth response type (e.g., "code" for authorization code flow)
   */
  responseType: string;

  /**
   * Client identifier for the OAuth client
   */
  clientId: string;

  /**
   * URL to redirect to after authorization
   */
  redirectUri: string;

  /**
   * Array of requested permission scopes
   */
  scope: string[];

  /**
   * Client state value to be returned in the redirect
   */
  state: string;

  /**
   * PKCE code challenge (RFC 7636)
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   */
  codeChallengeMethod?: string;

  /**
   * Resource parameter indicating target resource(s) (RFC 8707)
   */
  resource?: string | string[];
}

/**
 * OAuth client registration information
 */
export interface ClientInfo {
  /**
   * Unique identifier for the client
   */
  clientId: string;

  /**
   * Secret used to authenticate the client (stored as a hash)
   * Only present for confidential clients; undefined for public clients.
   */
  clientSecret?: string;

  /**
   * List of allowed redirect URIs for the client
   */
  redirectUris: string[];

  /**
   * Human-readable name of the client application
   */
  clientName?: string;

  /**
   * URL to the client's logo
   */
  logoUri?: string;

  /**
   * URL to the client's homepage
   */
  clientUri?: string;

  /**
   * URL to the client's privacy policy
   */
  policyUri?: string;

  /**
   * URL to the client's terms of service
   */
  tosUri?: string;

  /**
   * URL to the client's JSON Web Key Set for validating signatures
   */
  jwksUri?: string;

  /**
   * List of email addresses for contacting the client developers
   */
  contacts?: string[];

  /**
   * List of grant types the client supports
   */
  grantTypes?: string[];

  /**
   * List of response types the client supports
   */
  responseTypes?: string[];

  /**
   * Unix timestamp when the client was registered
   */
  registrationDate?: number;

  /**
   * The authentication method used by the client at the token endpoint.
   * Values include:
   * - 'client_secret_basic': Uses HTTP Basic Auth with client ID and secret (default for confidential clients)
   * - 'client_secret_post': Uses POST parameters for client authentication
   * - 'none': Used for public clients that can't securely store secrets (SPAs, mobile apps, etc.)
   *
   * Public clients use 'none', while confidential clients use either 'client_secret_basic' or 'client_secret_post'.
   */
  tokenEndpointAuthMethod: string;
}

/**
 * Options for completing an authorization request
 */
export interface CompleteAuthorizationOptions {
  /**
   * The original parsed authorization request
   */
  request: AuthRequest;

  /**
   * Identifier for the user granting the authorization
   */
  userId: string;

  /**
   * Application-specific metadata to associate with this grant
   */
  metadata: any;

  /**
   * List of scopes that were actually granted (may differ from requested scopes)
   */
  scope: string[];

  /**
   * Application-specific properties to include with API requests
   * authorized by this grant
   */
  props: any;

  /**
   * Revokes all existing grants for this user+client combination
   * after storing the new grant. Defaults to true. This prevents stale
   * tokens from causing infinite re-auth loops when props change.
   * Set to false to allow multiple concurrent grants per user+client.
   */
  revokeExistingGrants?: boolean;
}

/**
 * Authorization grant record
 */
export interface Grant {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Encrypted application-specific properties
   */
  encryptedProps: string;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the grant expires (if TTL is configured)
   */
  expiresAt?: number;

  /**
   * The hash of the current refresh token associated with this grant
   */
  refreshTokenId?: string;

  /**
   * Wrapped encryption key for the current refresh token
   */
  refreshTokenWrappedKey?: string;

  /**
   * The hash of the previous refresh token associated with this grant
   * This token is still valid until the new token is first used
   */
  previousRefreshTokenId?: string;

  /**
   * Wrapped encryption key for the previous refresh token
   */
  previousRefreshTokenWrappedKey?: string;

  /**
   * Unix timestamp when the previous refresh token was rotated out.
   * Used with refreshTokenGracePeriod to time-limit previous token validity.
   */
  previousRefreshTokenRotatedAt?: number;

  /**
   * The hash of the authorization code associated with this grant
   * Only present during the authorization code exchange process
   */
  authCodeId?: string;

  /**
   * Wrapped encryption key for the authorization code
   * Only present during the authorization code exchange process
   */
  authCodeWrappedKey?: string;

  /**
   * PKCE code challenge for this authorization
   * Only present during the authorization code exchange process
   */
  codeChallenge?: string;

  /**
   * PKCE code challenge method (plain or S256)
   * Only present during the authorization code exchange process
   */
  codeChallengeMethod?: string;

  /**
   * Resource parameter from authorization request (RFC 8707 Section 2.1)
   * Indicates the protected resource(s) for which access is requested
   */
  resource?: string | string[];
}

/**
 * OAuth 2.0 Token Response
 * The response returned when exchanging authorization codes or refresh tokens
 */
interface TokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  /**
   * Resource indicator(s) for the issued access token (RFC 8707 Section 2.2)
   * SHOULD be included to indicate the resource server(s) for which the token is valid
   */
  resource?: string | string[];
}

/**
 * Shared fields for Token and TokenSummary
 */
export interface TokenBase {
  /**
   * Unique identifier for the token (hash of the actual token)
   */
  id: string;

  /**
   * Identifier of the grant this token is associated with
   */
  grantId: string;

  /**
   * User ID associated with this token
   */
  userId: string;

  /**
   * Unix timestamp when the token was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the token expires
   */
  expiresAt: number;

  /**
   * Intended audience for this token (RFC 7519 Section 4.1.3)
   * Can be a single string or array of strings
   */
  audience?: string | string[];

  /**
   * List of scopes on this token
   */
  scope: string[];
}

/**
 * Token record stored in storage
 * Note: The actual token format is "{userId}:{grantId}:{random-secret}"
 * but we still only store the hash of the full token string.
 * This contains only access tokens; refresh tokens are stored within the grant records.
 */
export interface Token extends TokenBase {
  /**
   * The encryption key for props, wrapped with this token
   */
  wrappedEncryptionKey: string;

  /**
   * Denormalized grant information for faster access
   */
  grant: {
    /**
     * Client that received this grant
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Encrypted application-specific properties
     */
    encryptedProps: string;
  };
}

/**
 * Token record with decrypted properties
 * Derived from Token but with wrappedEncryptionKey removed and encryptedProps replaced with props
 */
export interface TokenSummary<T = any> extends TokenBase {
  /**
   * Denormalized grant information for faster access
   */
  grant: {
    /**
     * Client that received this grant
     */
    clientId: string;

    /**
     * List of scopes that were granted
     */
    scope: string[];

    /**
     * Decrypted application-specific properties
     */
    props: T;
  };
}

/**
 * Options for listing operations that support pagination
 */
export interface ListOptions {
  /**
   * Maximum number of items to return (max 1000)
   */
  limit?: number;

  /**
   * Cursor for pagination (from a previous listing operation)
   */
  cursor?: string;
}

/**
 * Result of a listing operation with pagination support
 */
export interface ListResult<T> {
  /**
   * The list of items
   */
  items: T[];

  /**
   * Cursor to get the next page of results, if there are more results
   */
  cursor?: string;
}

/**
 * Public representation of a grant, with sensitive data removed
 * Used for list operations where the complete grant data isn't needed
 */
export interface GrantSummary {
  /**
   * Unique identifier for the grant
   */
  id: string;

  /**
   * Client that received this grant
   */
  clientId: string;

  /**
   * User who authorized this grant
   */
  userId: string;

  /**
   * List of scopes that were granted
   */
  scope: string[];

  /**
   * Application-specific metadata associated with this grant
   */
  metadata: any;

  /**
   * Unix timestamp when the grant was created
   */
  createdAt: number;

  /**
   * Unix timestamp when the grant expires (if TTL is configured)
   */
  expiresAt?: number;
}

/**
 * Options for creating an access token
 */
interface CreateAccessTokenOptions {
  /**
   * User ID
   */
  userId: string;

  /**
   * Grant ID
   */
  grantId: string;

  /**
   * Client ID
   */
  clientId: string;

  /**
   * Token scopes
   */
  scope: string[];

  /**
   * Encrypted props for the token
   */
  encryptedProps: string;

  /**
   * Encryption key for the props
   */
  encryptionKey: CryptoKey;

  /**
   * TTL for the access token in seconds
   */
  expiresIn: number;

  /**
   * Optional audience/resource
   */
  audience?: string | string[];
}

/**
 * OAuth 2.0 Provider implementation.
 * Implements authorization code flow with support for refresh tokens
 * and dynamic client registration.
 */
export class OAuthProvider implements OAuthHelpers {
  #impl: OAuthProviderImpl;
  #helpers: OAuthHelpersImpl;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    this.#impl = new OAuthProviderImpl(options);
    this.#helpers = this.#impl.createOAuthHelpers();
  }

  /**
   * Main fetch handler
   * Routes requests to the appropriate handler based on the URL
   * @param request - The HTTP request
   * @returns A Promise resolving to an HTTP Response
   */
  fetch(request: Request): Promise<Response> {
    return this.#impl.fetch(request);
  }

  // OAuthHelpers methods delegated to the internal helpers instance

  parseAuthRequest(request: Request): Promise<AuthRequest> {
    return this.#helpers.parseAuthRequest(request);
  }

  lookupClient(clientId: string): Promise<ClientInfo | null> {
    return this.#helpers.lookupClient(clientId);
  }

  completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }> {
    return this.#helpers.completeAuthorization(options);
  }

  createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo> {
    return this.#helpers.createClient(clientInfo);
  }

  listClients(options?: ListOptions): Promise<ListResult<ClientInfo>> {
    return this.#helpers.listClients(options);
  }

  updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> {
    return this.#helpers.updateClient(clientId, updates);
  }

  deleteClient(clientId: string): Promise<void> {
    return this.#helpers.deleteClient(clientId);
  }

  listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>> {
    return this.#helpers.listUserGrants(userId, options);
  }

  revokeGrant(grantId: string, userId: string): Promise<void> {
    return this.#helpers.revokeGrant(grantId, userId);
  }

  unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null> {
    return this.#helpers.unwrapToken(token);
  }

  exchangeToken(options: ExchangeTokenOptions): Promise<TokenResponse> {
    return this.#helpers.exchangeToken(options);
  }
}

/**
 * Implementation class backing OAuthProvider.
 *
 * We use a PImpl pattern in `OAuthProvider` to make sure we don't inadvertently export any private
 * methods over RPC. Unfortunately, declaring a method "private" in TypeScript is merely a type
 * annotation, and does not actually prevent the method from being called from outside the class,
 * including over RPC.
 */
class OAuthProviderImpl {
  /**
   * Configuration options for the provider
   */
  options: OAuthProviderOptions;

  /**
   * Storage adapter for persisting OAuth data
   */
  storage: StorageAdapter;

  /**
   * Default handler for non-API requests
   */
  private defaultHandler: DefaultHandler;

  /**
   * Array of tuples of API routes and their validated handlers
   */
  private apiHandlers: Array<[string, ApiHandler]>;

  /**
   * Creates a new OAuth provider instance
   * @param options - Configuration options for the provider
   */
  constructor(options: OAuthProviderOptions) {
    // Store storage adapter
    this.storage = options.storage;

    // Initialize apiHandlers as an array
    this.apiHandlers = [];

    // Check if we have incompatible configuration
    const hasSingleHandlerConfig = !!(options.apiRoute && options.apiHandler);
    const hasMultiHandlerConfig = !!options.apiHandlers;

    if (hasSingleHandlerConfig && hasMultiHandlerConfig) {
      throw new TypeError(
        'Cannot use both apiRoute/apiHandler and apiHandlers. ' +
          'Use either apiRoute + apiHandler OR apiHandlers, not both.'
      );
    }

    if (!hasSingleHandlerConfig && !hasMultiHandlerConfig) {
      throw new TypeError(
        'Must provide either apiRoute + apiHandler OR apiHandlers. ' + 'No API route configuration provided.'
      );
    }

    // Validate default handler
    this.validateHandler(options.defaultHandler, 'defaultHandler');
    this.defaultHandler = options.defaultHandler;

    // Process and validate the API handlers
    if (hasSingleHandlerConfig) {
      // Single handler mode with apiRoute + apiHandler
      this.validateHandler(options.apiHandler!, 'apiHandler');

      // For single handler mode, process the apiRoute(s) and map them all to the single apiHandler
      if (Array.isArray(options.apiRoute)) {
        options.apiRoute.forEach((route, index) => {
          this.validateEndpoint(route, `apiRoute[${index}]`);
          this.apiHandlers.push([route, options.apiHandler!]);
        });
      } else {
        this.validateEndpoint(options.apiRoute!, 'apiRoute');
        this.apiHandlers.push([options.apiRoute!, options.apiHandler!]);
      }
    } else {
      // Multiple handlers mode with apiHandlers map
      for (const [route, handler] of Object.entries(options.apiHandlers!)) {
        this.validateEndpoint(route, `apiHandlers key: ${route}`);
        this.validateHandler(handler, `apiHandlers[${route}]`);
        this.apiHandlers.push([route, handler]);
      }
    }

    // Validate that the oauth endpoints are either absolute paths or full URLs
    this.validateEndpoint(options.authorizeEndpoint, 'authorizeEndpoint');
    this.validateEndpoint(options.tokenEndpoint, 'tokenEndpoint');
    if (options.clientRegistrationEndpoint) {
      this.validateEndpoint(options.clientRegistrationEndpoint, 'clientRegistrationEndpoint');
    }

    this.options = {
      accessTokenTTL: DEFAULT_ACCESS_TOKEN_TTL,
      refreshTokenTTL: 0,
      allowPlainPKCE: false,
      onError: ({ status, code, description }) =>
        console.warn(`OAuth error response: ${status} ${code} - ${description}`),
      ...options,
    };
  }

  /**
   * Helper to get a JSON value from storage
   */
  private async storageGetJson<T>(key: string): Promise<T | null> {
    const raw = await this.storage.get(key);
    return raw ? (JSON.parse(raw) as T) : null;
  }

  /**
   * Validates that an endpoint is either an absolute path or a full URL
   */
  private validateEndpoint(endpoint: string, name: string): void {
    if (this.isPath(endpoint)) {
      if (!endpoint.startsWith('/')) {
        throw new TypeError(`${name} path must be an absolute path starting with /`);
      }
    } else {
      try {
        new URL(endpoint);
      } catch (e) {
        throw new TypeError(`${name} must be either an absolute path starting with / or a valid URL`);
      }
    }
  }

  /**
   * Validates that a handler has a fetch method
   */
  private validateHandler(handler: any, name: string): void {
    if (typeof handler === 'object' && handler !== null && typeof handler.fetch === 'function') {
      return;
    }
    throw new TypeError(`${name} must be an object with a fetch method`);
  }

  /**
   * Main fetch handler
   * Routes requests to the appropriate handler based on the URL
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Special handling for OPTIONS requests (CORS preflight)
    if (request.method === 'OPTIONS') {
      // For API routes and OAuth endpoints, respond with CORS headers
      if (
        this.isApiRequest(url) ||
        url.pathname === '/.well-known/oauth-authorization-server' ||
        url.pathname === '/.well-known/oauth-protected-resource' ||
        this.isTokenEndpoint(url) ||
        (this.options.clientRegistrationEndpoint && this.isClientRegistrationEndpoint(url))
      ) {
        // Create an empty 204 No Content response with CORS headers
        return this.addCorsHeaders(
          new Response(null, {
            status: 204,
            headers: { 'Content-Length': '0' },
          }),
          request
        );
      }

      // For other routes, pass through to the default handler
    }

    // Handle .well-known/oauth-authorization-server
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      const response = await this.handleMetadataDiscovery(url);
      return this.addCorsHeaders(response, request);
    }

    // Handle .well-known/oauth-protected-resource (RFC 9728)
    if (url.pathname === '/.well-known/oauth-protected-resource') {
      const response = this.handleProtectedResourceMetadata(url);
      return this.addCorsHeaders(response, request);
    }

    // Handle token endpoint (including revocation)
    if (this.isTokenEndpoint(url)) {
      const parsed = await this.parseTokenEndpointRequest(request);

      // If parsing failed, return the error response
      if (parsed instanceof Response) {
        return this.addCorsHeaders(parsed, request);
      }

      let response: Response;
      if (parsed.isRevocationRequest) {
        response = await this.handleRevocationRequest(parsed.body);
      } else {
        response = await this.handleTokenRequest(parsed.body, parsed.clientInfo);
      }

      return this.addCorsHeaders(response, request);
    }

    // Handle client registration endpoint
    if (this.options.clientRegistrationEndpoint && this.isClientRegistrationEndpoint(url)) {
      const response = await this.handleClientRegistration(request);
      return this.addCorsHeaders(response, request);
    }

    // Check if it's an API request
    if (this.isApiRequest(url)) {
      const response = await this.handleApiRequest(request);
      return this.addCorsHeaders(response, request);
    }

    // Call the default handler
    // Note: We don't add CORS headers to default handler responses
    return this.defaultHandler.fetch(request);
  }

  /**
   * Decodes a token and returns token data with decrypted props
   */
  async unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null> {
    const parts = token.split(':');
    const isPossiblyInternalFormat = parts.length === 3;

    if (!isPossiblyInternalFormat) {
      return null;
    }

    // Retrieve the token from storage
    const [userId, grantId] = parts;
    const id = await generateTokenId(token);
    const tokenData = await this.storageGetJson<Token>(`token:${userId}:${grantId}:${id}`);

    // Return null if missing or expired
    if (!tokenData) {
      return null;
    }
    const now = Math.floor(Date.now() / 1e3);
    if (tokenData.expiresAt < now) {
      return null;
    }

    // Decrypt the props
    const encryptionKey = await unwrapKeyWithToken(token, tokenData.wrappedEncryptionKey);
    const decryptedProps = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);

    // Return the token data with decrypted instead of encrypted props
    const { grant } = tokenData;
    return {
      id: tokenData.id,
      grantId: tokenData.grantId,
      userId: tokenData.userId,
      createdAt: tokenData.createdAt,
      expiresAt: tokenData.expiresAt,
      audience: tokenData.audience,
      scope: tokenData.scope || grant.scope,
      grant: {
        clientId: grant.clientId,
        scope: grant.scope,
        props: decryptedProps as T,
      },
    };
  }

  /**
   * Determines if an endpoint configuration is a path or a full URL
   */
  private isPath(endpoint: string): boolean {
    return endpoint.startsWith('/');
  }

  /**
   * Matches a URL against an endpoint pattern that can be a full URL or just a path
   */
  private matchEndpoint(url: URL, endpoint: string): boolean {
    if (this.isPath(endpoint)) {
      return url.pathname === endpoint;
    } else {
      const endpointUrl = new URL(endpoint);
      return url.hostname === endpointUrl.hostname && url.pathname === endpointUrl.pathname;
    }
  }

  /**
   * Checks if a URL matches the configured token endpoint
   */
  private isTokenEndpoint(url: URL): boolean {
    return this.matchEndpoint(url, this.options.tokenEndpoint);
  }

  /**
   * Checks if a URL matches the configured client registration endpoint
   */
  private isClientRegistrationEndpoint(url: URL): boolean {
    if (!this.options.clientRegistrationEndpoint) return false;
    return this.matchEndpoint(url, this.options.clientRegistrationEndpoint);
  }

  /**
   * Parses and validates a token endpoint request (used for both token exchange and revocation)
   */
  private async parseTokenEndpointRequest(
    request: Request
  ): Promise<
    | {
        body: any;
        clientInfo: ClientInfo;
        isRevocationRequest: boolean;
      }
    | Response
  > {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', 'Method not allowed', 405);
    }

    let contentType = request.headers.get('Content-Type') || '';

    // According to OAuth 2.0 RFC 6749/7009, requests MUST use application/x-www-form-urlencoded
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return this.createErrorResponse('invalid_request', 'Content-Type must be application/x-www-form-urlencoded', 400);
    }

    let body: any = {};

    // Process application/x-www-form-urlencoded
    const formData = await request.formData();
    for (const [key, value] of formData.entries()) {
      // RFC 8707: resource parameter can appear multiple times
      const allValues = formData.getAll(key);
      body[key] = allValues.length > 1 ? allValues : value;
    }

    // Get client ID from request
    const authHeader = request.headers.get('Authorization');
    let clientId = '';
    let clientSecret = '';

    if (authHeader && authHeader.startsWith('Basic ')) {
      // Basic auth
      const credentials = atob(authHeader.substring(6));
      const [id, secret] = credentials.split(':', 2);
      clientId = decodeURIComponent(id);
      clientSecret = decodeURIComponent(secret || '');
    } else {
      // Form parameters
      clientId = body.client_id;
      clientSecret = body.client_secret || '';
    }

    if (!clientId) {
      return this.createErrorResponse('invalid_client', 'Client ID is required', 401);
    }

    // Verify client exists
    const clientInfo = await this.getClient(clientId);
    if (!clientInfo) {
      return this.createErrorResponse('invalid_client', 'Client not found', 401);
    }

    // Determine authentication requirements based on token endpoint auth method
    const isPublicClient = clientInfo.tokenEndpointAuthMethod === 'none';

    // For confidential clients, validate the secret
    if (!isPublicClient) {
      if (!clientSecret) {
        return this.createErrorResponse('invalid_client', 'Client authentication failed: missing client_secret', 401);
      }

      // Verify the client secret matches
      if (!clientInfo.clientSecret) {
        return this.createErrorResponse(
          'invalid_client',
          'Client authentication failed: client has no registered secret',
          401
        );
      }

      const providedSecretHash = await hashSecret(clientSecret);
      if (providedSecretHash !== clientInfo.clientSecret) {
        return this.createErrorResponse('invalid_client', 'Client authentication failed: invalid client_secret', 401);
      }
    }

    // Determine if this is a revocation request
    // RFC 7009: Revocation requests have 'token' parameter but no 'grant_type'
    const isRevocationRequest = !body.grant_type && !!body.token;

    return {
      body,
      clientInfo,
      isRevocationRequest,
    };
  }

  /**
   * Checks if a URL matches a specific API route
   */
  private matchApiRoute(url: URL, route: string): boolean {
    if (this.isPath(route)) {
      if (route === '/') {
        return url.pathname === '/';
      }
      return url.pathname.startsWith(route);
    } else {
      const apiUrl = new URL(route);
      return url.hostname === apiUrl.hostname && url.pathname.startsWith(apiUrl.pathname);
    }
  }

  /**
   * Checks if a URL is an API request based on the configured API route(s)
   */
  private isApiRequest(url: URL): boolean {
    for (const [route, _] of this.apiHandlers) {
      if (this.matchApiRoute(url, route)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Finds the appropriate API handler for a URL
   */
  private findApiHandlerForUrl(url: URL): ApiHandler | undefined {
    for (const [route, handler] of this.apiHandlers) {
      if (this.matchApiRoute(url, route)) {
        return handler;
      }
    }
    return undefined;
  }

  /**
   * Gets the full URL for an endpoint, using the provided request URL's
   * origin for endpoints specified as just paths
   */
  private getFullEndpointUrl(endpoint: string, requestUrl: URL): string {
    if (this.isPath(endpoint)) {
      return `${requestUrl.origin}${endpoint}`;
    } else {
      return endpoint;
    }
  }

  /**
   * Adds CORS headers to a response
   */
  private addCorsHeaders(response: Response, request: Request): Response {
    const origin = request.headers.get('Origin');
    if (!origin) {
      return response;
    }

    const newResponse = new Response(response.body, response);
    newResponse.headers.set('Access-Control-Allow-Origin', origin);
    newResponse.headers.set('Access-Control-Allow-Methods', '*');
    newResponse.headers.set('Access-Control-Allow-Headers', 'Authorization, *');
    newResponse.headers.set('Access-Control-Max-Age', '86400');

    return newResponse;
  }

  /**
   * Handles the OAuth metadata discovery endpoint
   * Implements RFC 8414 for OAuth Server Metadata
   */
  private async handleMetadataDiscovery(requestUrl: URL): Promise<Response> {
    const tokenEndpoint = this.getFullEndpointUrl(this.options.tokenEndpoint, requestUrl);
    const authorizeEndpoint = this.getFullEndpointUrl(this.options.authorizeEndpoint, requestUrl);

    let registrationEndpoint: string | undefined = undefined;
    if (this.options.clientRegistrationEndpoint) {
      registrationEndpoint = this.getFullEndpointUrl(this.options.clientRegistrationEndpoint, requestUrl);
    }

    // Determine supported response types
    const responseTypesSupported = ['code'];
    if (this.options.allowImplicitFlow) {
      responseTypesSupported.push('token');
    }

    // Determine supported grant types
    const grantTypesSupported = [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN];
    if (this.options.allowTokenExchangeGrant) {
      grantTypesSupported.push(GrantType.TOKEN_EXCHANGE);
    }

    const metadata = {
      issuer: new URL(tokenEndpoint).origin,
      authorization_endpoint: authorizeEndpoint,
      token_endpoint: tokenEndpoint,
      registration_endpoint: registrationEndpoint,
      scopes_supported: this.options.scopesSupported,
      response_types_supported: responseTypesSupported,
      response_modes_supported: ['query'],
      grant_types_supported: grantTypesSupported,
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      revocation_endpoint: tokenEndpoint,
      code_challenge_methods_supported: this.options.allowPlainPKCE ? ['plain', 'S256'] : ['S256'],
      client_id_metadata_document_supported: !!this.options.clientIdMetadataDocumentEnabled,
    };

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles the OAuth Protected Resource Metadata endpoint
   * Implements RFC 9728 for OAuth Protected Resource Metadata
   */
  private handleProtectedResourceMetadata(requestUrl: URL): Response {
    const rm = this.options.resourceMetadata;

    const tokenEndpointUrl = this.getFullEndpointUrl(this.options.tokenEndpoint, requestUrl);
    const authServerOrigin = new URL(tokenEndpointUrl).origin;

    const metadata: Record<string, unknown> = {
      resource: rm?.resource ?? requestUrl.origin,
      authorization_servers: rm?.authorization_servers ?? [authServerOrigin],
      scopes_supported: rm?.scopes_supported ?? this.options.scopesSupported,
      bearer_methods_supported: rm?.bearer_methods_supported ?? ['header'],
    };

    if (rm?.resource_name) {
      metadata.resource_name = rm.resource_name;
    }

    return new Response(JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles client authentication and token issuance via the token endpoint
   */
  private async handleTokenRequest(body: any, clientInfo: ClientInfo): Promise<Response> {
    const grantType = body.grant_type;

    if (grantType === GrantType.AUTHORIZATION_CODE) {
      return this.handleAuthorizationCodeGrant(body, clientInfo);
    } else if (grantType === GrantType.REFRESH_TOKEN) {
      return this.handleRefreshTokenGrant(body, clientInfo);
    } else if (grantType === GrantType.TOKEN_EXCHANGE && this.options.allowTokenExchangeGrant) {
      return this.handleTokenExchangeGrant(body, clientInfo);
    } else {
      return this.createErrorResponse('unsupported_grant_type', 'Grant type not supported');
    }
  }

  /**
   * Handles the authorization code grant type
   */
  private async handleAuthorizationCodeGrant(body: any, clientInfo: ClientInfo): Promise<Response> {
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const codeVerifier = body.code_verifier;

    if (!code) {
      return this.createErrorResponse('invalid_request', 'Authorization code is required');
    }

    // Parse the authorization code to extract user ID and grant ID
    const codeParts = code.split(':');
    if (codeParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', 'Invalid authorization code format');
    }

    const [userId, grantId, _] = codeParts;

    // Get the grant
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData = await this.storageGetJson<Grant>(grantKey);

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', 'Grant not found or authorization code expired');
    }

    // Verify that the grant contains an auth code hash
    if (!grantData.authCodeId) {
      try {
        await this.createOAuthHelpers().revokeGrant(grantId, userId);
      } catch {
        // Best-effort revocation
      }
      return this.createErrorResponse('invalid_grant', 'Authorization code already used');
    }

    // Verify the authorization code by comparing its hash to the one in the grant
    const codeHash = await hashSecret(code);
    if (codeHash !== grantData.authCodeId) {
      return this.createErrorResponse('invalid_grant', 'Invalid authorization code');
    }

    // Verify client ID matches
    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', 'Client ID mismatch');
    }

    // Check if PKCE is being used
    const isPkceEnabled = !!grantData.codeChallenge;

    // OAuth 2.1 requires redirect_uri parameter unless PKCE is used
    if (!redirectUri && !isPkceEnabled) {
      return this.createErrorResponse('invalid_request', 'redirect_uri is required when not using PKCE');
    }

    // Verify redirect URI if provided
    if (redirectUri && !isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
      return this.createErrorResponse('invalid_grant', 'Invalid redirect URI');
    }

    // Reject if code_verifier is provided but PKCE wasn't used in authorization
    if (!isPkceEnabled && codeVerifier) {
      return this.createErrorResponse('invalid_request', 'code_verifier provided for a flow that did not use PKCE');
    }

    // Verify PKCE code_verifier if code_challenge was provided during authorization
    if (isPkceEnabled) {
      if (!codeVerifier) {
        return this.createErrorResponse('invalid_request', 'code_verifier is required for PKCE');
      }

      let calculatedChallenge: string;

      if (grantData.codeChallengeMethod === 'S256') {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        calculatedChallenge = base64UrlEncode(String.fromCharCode(...hashArray));
      } else {
        calculatedChallenge = codeVerifier;
      }

      if (calculatedChallenge !== grantData.codeChallenge) {
        return this.createErrorResponse('invalid_grant', 'Invalid PKCE code_verifier');
      }
    }

    // Define the access token TTL, may be updated by callback if provided
    let accessTokenTTL = this.options.accessTokenTTL!;
    // Define the refresh token TTL, may be updated by callback if provided
    let refreshTokenTTL = this.options.refreshTokenTTL;

    // Get the encryption key for props by unwrapping it using the auth code
    const encryptionKey = await unwrapKeyWithToken(code, grantData.authCodeWrappedKey!);

    // Default to using the same encryption key and props for both grant and access token
    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    // Parse and validate scope parameter for downscoping (RFC 6749 Section 3.3)
    let tokenScopes: string[] = this.downscope(body.scope, grantData.scope);

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.AUTHORIZATION_CODE,
        clientId: clientInfo.clientId,
        userId: userId,
        scope: grantData.scope,
        requestedScope: tokenScopes,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }

        if ('refreshTokenTTL' in callbackResult) {
          refreshTokenTTL = callbackResult.refreshTokenTTL;
        }

        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, grantData.scope);
        }
      }

      // Re-encrypt the potentially updated grant props
      const grantResult = await encryptProps(grantProps);
      grantData.encryptedProps = grantResult.encryptedData;
      grantEncryptionKey = grantResult.key;

      // Re-encrypt the access token props if they're different from grant props
      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    // Calculate the access token expiration time
    const now = Math.floor(Date.now() / 1000);

    // Determine if we should issue a refresh token
    const useRefreshToken = refreshTokenTTL !== 0;

    // Update the grant: remove auth code fields
    delete grantData.authCodeId;
    delete grantData.codeChallenge;
    delete grantData.codeChallengeMethod;
    delete grantData.authCodeWrappedKey;

    // Only generate refresh token if issuing one
    let refreshToken: string | undefined;

    if (useRefreshToken) {
      const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
      refreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
      const refreshTokenId = await generateTokenId(refreshToken);
      const refreshTokenWrappedKey = await wrapKeyWithToken(refreshToken, grantEncryptionKey);

      const expiresAt = refreshTokenTTL !== undefined ? now + refreshTokenTTL : undefined;

      grantData.refreshTokenId = refreshTokenId;
      grantData.refreshTokenWrappedKey = refreshTokenWrappedKey;
      grantData.previousRefreshTokenId = undefined;
      grantData.previousRefreshTokenWrappedKey = undefined;
      grantData.expiresAt = expiresAt;
    }

    // Save the updated grant
    await this.saveGrantWithTTL(grantKey, grantData, now);

    // Parse and validate resource parameter (RFC 8707)
    if (body.resource && grantData.resource) {
      const requestedResources = Array.isArray(body.resource) ? body.resource : [body.resource];
      const grantedResources = Array.isArray(grantData.resource) ? grantData.resource : [grantData.resource];

      for (const requested of requestedResources) {
        if (!grantedResources.includes(requested)) {
          return this.createErrorResponse(
            'invalid_target',
            'Requested resource was not included in the authorization request'
          );
        }
      }
    }

    const audience = parseResourceParameter(body.resource || grantData.resource);
    if ((body.resource || grantData.resource) && !audience) {
      return this.createErrorResponse(
        'invalid_target',
        'The resource parameter must be a valid absolute URI without a fragment'
      );
    }

    // Create and store access token
    const accessToken = await this.createAccessToken({
      userId,
      grantId,
      clientId: grantData.clientId,
      scope: tokenScopes,
      encryptedProps: encryptedAccessTokenProps,
      encryptionKey: accessTokenEncryptionKey,
      expiresIn: accessTokenTTL,
      audience,
    });

    // Build the response
    const tokenResponse: TokenResponse = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      scope: tokenScopes.join(' '),
    };

    if (refreshToken) {
      tokenResponse.refresh_token = refreshToken;
    }

    if (audience) {
      tokenResponse.resource = audience;
    }

    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles the refresh token grant type
   */
  private async handleRefreshTokenGrant(body: any, clientInfo: ClientInfo): Promise<Response> {
    const refreshToken = body.refresh_token;

    if (!refreshToken) {
      return this.createErrorResponse('invalid_request', 'Refresh token is required');
    }

    const tokenParts = refreshToken.split(':');
    if (tokenParts.length !== 3) {
      return this.createErrorResponse('invalid_grant', 'Invalid token format');
    }

    const [userId, grantId, _] = tokenParts;
    const providedTokenHash = await generateTokenId(refreshToken);

    const grantKey = `grant:${userId}:${grantId}`;
    const grantData = await this.storageGetJson<Grant>(grantKey);

    if (!grantData) {
      return this.createErrorResponse('invalid_grant', 'Grant not found');
    }

    const isCurrentToken = grantData.refreshTokenId === providedTokenHash;
    const isPreviousToken = grantData.previousRefreshTokenId === providedTokenHash;

    if (!isCurrentToken && !isPreviousToken) {
      // Replay detection: token was valid once but has been fully superseded
      if (this.options.revokeGrantOnRefreshTokenReplay) {
        await this.createOAuthHelpers().revokeGrant(grantId, userId);
      }
      return this.createErrorResponse('invalid_grant', 'Invalid refresh token');
    }

    // Check grace period for previous refresh token
    if (isPreviousToken && this.options.refreshTokenGracePeriod !== undefined) {
      const rotatedAt = grantData.previousRefreshTokenRotatedAt;
      if (rotatedAt !== undefined) {
        const now = Math.floor(Date.now() / 1000);
        if (now - rotatedAt >= this.options.refreshTokenGracePeriod) {
          return this.createErrorResponse('invalid_grant', 'Previous refresh token has expired');
        }
      }
    }

    if (grantData.clientId !== clientInfo.clientId) {
      return this.createErrorResponse('invalid_grant', 'Client ID mismatch');
    }

    // Check if the refresh token has expired
    if (grantData.expiresAt !== undefined) {
      const now = Math.floor(Date.now() / 1000);
      if (now >= grantData.expiresAt) {
        return this.createErrorResponse('invalid_grant', 'Refresh token has expired');
      }
    }

    // Generate new access token with embedded user and grant IDs
    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newAccessToken = `${userId}:${grantId}:${accessTokenSecret}`;
    const accessTokenId = await generateTokenId(newAccessToken);

    let accessTokenTTL = this.options.accessTokenTTL!;

    // Determine which wrapped key to use for unwrapping
    let wrappedKeyToUse: string;
    if (isCurrentToken) {
      wrappedKeyToUse = grantData.refreshTokenWrappedKey!;
    } else {
      wrappedKeyToUse = grantData.previousRefreshTokenWrappedKey!;
    }

    const encryptionKey = await unwrapKeyWithToken(refreshToken, wrappedKeyToUse);

    let grantEncryptionKey = encryptionKey;
    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = grantData.encryptedProps;

    let tokenScopes = this.downscope(body.scope, grantData.scope);

    let grantPropsChanged = false;

    // Process token exchange callback if provided
    if (this.options.tokenExchangeCallback) {
      const decryptedProps = await decryptProps(encryptionKey, grantData.encryptedProps);

      let grantProps = decryptedProps;
      let accessTokenProps = decryptedProps;

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.REFRESH_TOKEN,
        clientId: clientInfo.clientId,
        userId: userId,
        scope: grantData.scope,
        requestedScope: tokenScopes,
        props: decryptedProps,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        if (callbackResult.newProps) {
          grantProps = callbackResult.newProps;
          grantPropsChanged = true;
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = callbackResult.accessTokenTTL;
        }

        if ('refreshTokenTTL' in callbackResult) {
          return this.createErrorResponse(
            'invalid_request',
            'refreshTokenTTL cannot be changed during refresh token exchange'
          );
        }

        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, grantData.scope);
        }
      }

      if (grantPropsChanged) {
        const grantResult = await encryptProps(grantProps);
        grantData.encryptedProps = grantResult.encryptedData;

        if (grantResult.key !== encryptionKey) {
          grantEncryptionKey = grantResult.key;
          wrappedKeyToUse = await wrapKeyWithToken(refreshToken, grantEncryptionKey);
        } else {
          grantEncryptionKey = grantResult.key;
        }
      }

      if (accessTokenProps !== grantProps) {
        const tokenResult = await encryptProps(accessTokenProps);
        encryptedAccessTokenProps = tokenResult.encryptedData;
        accessTokenEncryptionKey = tokenResult.key;
      } else {
        encryptedAccessTokenProps = grantData.encryptedProps;
        accessTokenEncryptionKey = grantEncryptionKey;
      }
    }

    const now = Math.floor(Date.now() / 1000);

    // Clamp access token TTL to not exceed refresh token's remaining lifetime
    if (grantData.expiresAt !== undefined) {
      const remainingRefreshTokenLifetime = grantData.expiresAt - now;
      if (remainingRefreshTokenLifetime > 0) {
        accessTokenTTL = Math.min(accessTokenTTL, remainingRefreshTokenLifetime);
      }
    }

    const accessTokenExpiresAt = now + accessTokenTTL;

    const accessTokenWrappedKey = await wrapKeyWithToken(newAccessToken, accessTokenEncryptionKey);

    // Generate new refresh token for rotation
    const refreshTokenSecret = generateRandomString(TOKEN_LENGTH);
    const newRefreshToken = `${userId}:${grantId}:${refreshTokenSecret}`;
    const newRefreshTokenId = await generateTokenId(newRefreshToken);
    const newRefreshTokenWrappedKey = await wrapKeyWithToken(newRefreshToken, grantEncryptionKey);

    // Token rotation (see original for rationale on keeping previous token valid)
    grantData.previousRefreshTokenId = providedTokenHash;
    grantData.previousRefreshTokenWrappedKey = wrappedKeyToUse;
    grantData.previousRefreshTokenRotatedAt = Math.floor(Date.now() / 1000);
    grantData.refreshTokenId = newRefreshTokenId;
    grantData.refreshTokenWrappedKey = newRefreshTokenWrappedKey;

    await this.saveGrantWithTTL(grantKey, grantData, now);

    // Parse and validate resource parameter (RFC 8707)
    if (body.resource && grantData.resource) {
      const requestedResources = Array.isArray(body.resource) ? body.resource : [body.resource];
      const grantedResources = Array.isArray(grantData.resource) ? grantData.resource : [grantData.resource];

      for (const requested of requestedResources) {
        if (!grantedResources.includes(requested)) {
          return this.createErrorResponse(
            'invalid_target',
            'Requested resource was not included in the authorization request'
          );
        }
      }
    }

    const audience = parseResourceParameter(body.resource || grantData.resource);
    if ((body.resource || grantData.resource) && !audience) {
      return this.createErrorResponse(
        'invalid_target',
        'The resource parameter must be a valid absolute URI without a fragment'
      );
    }

    // Store new access token
    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      audience: audience,
      scope: tokenScopes,
      wrappedEncryptionKey: accessTokenWrappedKey,
      grant: {
        clientId: grantData.clientId,
        scope: grantData.scope,
        encryptedProps: encryptedAccessTokenProps,
      },
    };

    await this.storage.put(`token:${userId}:${grantId}:${accessTokenId}`, JSON.stringify(accessTokenData), {
      expirationTtl: accessTokenTTL,
    });

    const tokenResponse: TokenResponse = {
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      refresh_token: newRefreshToken,
      scope: tokenScopes.join(' '),
    };

    if (audience) {
      tokenResponse.resource = audience;
    }

    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Core token exchange logic (RFC 8693)
   */
  async exchangeToken(
    subjectToken: string,
    requestedScopes: string[] | undefined,
    requestedResource: string | string[] | undefined,
    expiresIn: number | undefined,
    clientInfo: ClientInfo,
    actorToken?: string,
    actorTokenType?: string
  ): Promise<TokenResponse & { issued_token_type?: string }> {
    const tokenSummary = await this.unwrapToken(subjectToken);
    if (!tokenSummary) {
      throw new OAuthError('invalid_grant', 'Invalid or expired subject token');
    }

    const grantKey = `grant:${tokenSummary.userId}:${tokenSummary.grantId}`;
    const grantData = await this.storageGetJson<Grant>(grantKey);
    if (!grantData) {
      throw new OAuthError('invalid_grant', 'Grant not found');
    }

    let tokenScopes: string[] = this.downscope(requestedScopes, grantData.scope);

    let newAudience: string | string[] | undefined = tokenSummary.audience;
    if (requestedResource) {
      if (grantData.resource) {
        const requestedResources = Array.isArray(requestedResource) ? requestedResource : [requestedResource];
        const grantedResources = Array.isArray(grantData.resource) ? grantData.resource : [grantData.resource];

        for (const requested of requestedResources) {
          if (!grantedResources.includes(requested)) {
            throw new OAuthError('invalid_target', 'Requested resource was not included in the authorization request');
          }
        }
      }

      const parsedResource = parseResourceParameter(requestedResource);
      if (!parsedResource) {
        throw new OAuthError(
          'invalid_target',
          'The resource parameter must be a valid absolute URI without a fragment'
        );
      }
      newAudience = parsedResource;
    }

    const now = Math.floor(Date.now() / 1000);
    const subjectTokenRemainingLifetime = tokenSummary.expiresAt - now;
    let accessTokenTTL = this.options.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL;

    if (expiresIn !== undefined) {
      if (expiresIn <= 0) {
        throw new OAuthError('invalid_request', 'Invalid expires_in parameter');
      }
      accessTokenTTL = Math.min(expiresIn, subjectTokenRemainingLifetime);
    } else {
      accessTokenTTL = Math.min(accessTokenTTL, subjectTokenRemainingLifetime);
    }

    const subjectTokenData = await this.storageGetJson<Token>(
      `token:${tokenSummary.userId}:${tokenSummary.grantId}:${tokenSummary.id}`
    );

    if (!subjectTokenData) {
      throw new OAuthError('invalid_grant', 'Subject token data not found');
    }

    const encryptionKey = await unwrapKeyWithToken(subjectToken, subjectTokenData.wrappedEncryptionKey);

    let accessTokenEncryptionKey = encryptionKey;
    let encryptedAccessTokenProps = subjectTokenData.grant.encryptedProps;

    // Resolve actor token if provided
    let actorTokenInfo: TokenSummary | undefined;
    if (actorToken) {
      const unwrapped = await this.unwrapToken(actorToken);
      if (unwrapped) {
        actorTokenInfo = unwrapped;
      }

      // Validate may_act claim on subject token if actor token is resolved
      if (actorTokenInfo) {
        const subjectDecrypted = await decryptProps(encryptionKey, subjectTokenData.grant.encryptedProps);
        if (subjectDecrypted?.may_act?.sub && subjectDecrypted.may_act.sub !== actorTokenInfo.userId) {
          throw new OAuthError(
            'invalid_grant',
            'Actor is not authorized to act on behalf of the subject (may_act constraint)'
          );
        }
      }
    }

    if (this.options.tokenExchangeCallback) {
      const decryptedProps = await decryptProps(encryptionKey, subjectTokenData.grant.encryptedProps);

      const callbackOptions: TokenExchangeCallbackOptions = {
        grantType: GrantType.TOKEN_EXCHANGE,
        clientId: clientInfo.clientId,
        userId: tokenSummary.userId,
        scope: tokenSummary.grant.scope,
        requestedScope: tokenScopes,
        props: decryptedProps,
        actorToken,
        actorTokenType,
        actorTokenInfo,
      };

      const callbackResult = await Promise.resolve(this.options.tokenExchangeCallback(callbackOptions));

      if (callbackResult) {
        let accessTokenProps = decryptedProps;

        if (callbackResult.newProps) {
          if (!callbackResult.accessTokenProps) {
            accessTokenProps = callbackResult.newProps;
          }
        }

        if (callbackResult.accessTokenProps) {
          accessTokenProps = callbackResult.accessTokenProps;
        }

        if (callbackResult.accessTokenTTL !== undefined) {
          accessTokenTTL = Math.min(callbackResult.accessTokenTTL, subjectTokenRemainingLifetime);
        }

        if (accessTokenProps !== decryptedProps) {
          const tokenResult = await encryptProps(accessTokenProps);
          encryptedAccessTokenProps = tokenResult.encryptedData;
          accessTokenEncryptionKey = tokenResult.key;
        }

        if (callbackResult.accessTokenScope) {
          tokenScopes = this.downscope(callbackResult.accessTokenScope, grantData.scope);
        }
      }
    }

    const newAccessToken = await this.createAccessToken({
      userId: tokenSummary.userId,
      grantId: tokenSummary.grantId,
      clientId: tokenSummary.grant.clientId,
      scope: tokenScopes,
      encryptedProps: encryptedAccessTokenProps,
      encryptionKey: accessTokenEncryptionKey,
      expiresIn: accessTokenTTL,
      audience: newAudience,
    });

    const tokenResponse: TokenResponse & { issued_token_type?: string } = {
      access_token: newAccessToken,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'bearer',
      expires_in: accessTokenTTL,
      scope: tokenScopes.join(' '),
    };

    if (newAudience) {
      tokenResponse.resource = newAudience;
    }

    return tokenResponse;
  }

  /**
   * Handles OAuth 2.0 token exchange requests (RFC 8693)
   */
  private async handleTokenExchangeGrant(body: any, clientInfo: ClientInfo): Promise<Response> {
    const subjectToken = body.subject_token;
    const subjectTokenType = body.subject_token_type;
    const requestedTokenType = body.requested_token_type || 'urn:ietf:params:oauth:token-type:access_token';
    const requestedScope = body.scope;
    const requestedResource = body.resource;
    const actorToken = body.actor_token;
    const actorTokenType = body.actor_token_type;

    if (!subjectToken) {
      return this.createErrorResponse('invalid_request', 'subject_token is required');
    }

    if (!subjectTokenType) {
      return this.createErrorResponse('invalid_request', 'subject_token_type is required');
    }

    if (subjectTokenType !== 'urn:ietf:params:oauth:token-type:access_token') {
      return this.createErrorResponse('invalid_request', 'Only access_token subject_token_type is supported');
    }

    if (requestedTokenType !== 'urn:ietf:params:oauth:token-type:access_token') {
      return this.createErrorResponse('invalid_request', 'Only access_token requested_token_type is supported');
    }

    // actor_token_type is required when actor_token is present (RFC 8693 Section 2.1)
    if (actorToken && !actorTokenType) {
      return this.createErrorResponse(
        'invalid_request',
        'actor_token_type is required when actor_token is present'
      );
    }

    if (actorTokenType && actorTokenType !== 'urn:ietf:params:oauth:token-type:access_token') {
      return this.createErrorResponse('invalid_request', 'Only access_token actor_token_type is supported');
    }

    let requestedScopes: string[] | undefined;
    if (requestedScope) {
      if (typeof requestedScope === 'string') {
        requestedScopes = requestedScope.split(' ').filter(Boolean);
      } else if (Array.isArray(requestedScope)) {
        requestedScopes = requestedScope;
      } else {
        return this.createErrorResponse('invalid_request', 'Invalid scope parameter format');
      }
    }

    let expiresIn: number | undefined;
    if (body.expires_in !== undefined) {
      const requestedTTL = parseInt(body.expires_in, 10);
      if (isNaN(requestedTTL) || requestedTTL <= 0) {
        return this.createErrorResponse('invalid_request', 'Invalid expires_in parameter');
      }
      expiresIn = requestedTTL;
    }

    try {
      const tokenResponse = await this.exchangeToken(
        subjectToken,
        requestedScopes,
        requestedResource,
        expiresIn,
        clientInfo,
        actorToken,
        actorTokenType
      );

      return new Response(JSON.stringify(tokenResponse), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      if (error instanceof OAuthError) {
        return this.createErrorResponse(error.code, error.message);
      }
      throw error;
    }
  }

  /**
   * Handles OAuth 2.0 token revocation requests (RFC 7009)
   */
  private async handleRevocationRequest(body: any): Promise<Response> {
    return this.revokeToken(body);
  }

  private async revokeToken(body: any): Promise<Response> {
    const token = body.token;

    if (!token) {
      return this.createErrorResponse('invalid_request', 'Token parameter is required');
    }
    const tokenParts = token.split(':');
    if (tokenParts.length !== 3) {
      return new Response('', { status: 200 });
    }

    const [userId, grantId, _] = tokenParts;
    const tokenId = await generateTokenId(token);

    const isAccessToken = await this.validateAccessToken(tokenId, userId, grantId);
    const isRefreshToken = await this.validateRefreshToken(tokenId, userId, grantId);

    if (isAccessToken) {
      await this.revokeSpecificAccessToken(tokenId, userId, grantId);
    } else if (isRefreshToken) {
      await this.createOAuthHelpers().revokeGrant(grantId, userId);
    }
    return new Response('', { status: 200 });
  }

  private async revokeSpecificAccessToken(tokenId: string, userId: string, grantId: string): Promise<void> {
    const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
    await this.storage.delete(tokenKey);
  }

  private async validateAccessToken(tokenId: string, userId: string, grantId: string): Promise<boolean> {
    const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
    const tokenData = await this.storageGetJson<Token>(tokenKey);

    if (!tokenData) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    return tokenData.expiresAt >= now;
  }

  private async validateRefreshToken(tokenId: string, userId: string, grantId: string): Promise<boolean> {
    const grantKey = `grant:${userId}:${grantId}`;
    const grantData = await this.storageGetJson<Grant>(grantKey);

    if (!grantData) {
      return false;
    }

    return grantData.refreshTokenId === tokenId || grantData.previousRefreshTokenId === tokenId;
  }

  /**
   * Handles the dynamic client registration endpoint (RFC 7591)
   */
  private async handleClientRegistration(request: Request): Promise<Response> {
    if (!this.options.clientRegistrationEndpoint) {
      return this.createErrorResponse('not_implemented', 'Client registration is not enabled', 501);
    }

    if (request.method !== 'POST') {
      return this.createErrorResponse('invalid_request', 'Method not allowed', 405);
    }

    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > 1048576) {
      return this.createErrorResponse('invalid_request', 'Request payload too large, must be under 1 MiB', 413);
    }

    let clientMetadata;
    try {
      const text = await request.text();
      if (text.length > 1048576) {
        return this.createErrorResponse('invalid_request', 'Request payload too large, must be under 1 MiB', 413);
      }
      clientMetadata = JSON.parse(text);
    } catch (error) {
      return this.createErrorResponse('invalid_request', 'Invalid JSON payload', 400);
    }

    const authMethod =
      OAuthProviderImpl.validateStringField(clientMetadata.token_endpoint_auth_method) || 'client_secret_basic';
    const isPublicClient = authMethod === 'none';

    if (isPublicClient && this.options.disallowPublicClientRegistration) {
      return this.createErrorResponse('invalid_client_metadata', 'Public client registration is not allowed');
    }

    const clientId = generateRandomString(16);

    let clientSecret: string | undefined;
    let hashedSecret: string | undefined;

    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      hashedSecret = await hashSecret(clientSecret);
    }

    let clientInfo: ClientInfo;
    try {
      const redirectUris = OAuthProviderImpl.validateStringArray(clientMetadata.redirect_uris);
      if (!redirectUris || redirectUris.length === 0) {
        throw new Error('At least one redirect URI is required');
      }

      for (const uri of redirectUris) {
        validateRedirectUriScheme(uri);
      }

      clientInfo = {
        clientId,
        redirectUris,
        clientName: OAuthProviderImpl.validateStringField(clientMetadata.client_name),
        logoUri: OAuthProviderImpl.validateStringField(clientMetadata.logo_uri),
        clientUri: OAuthProviderImpl.validateStringField(clientMetadata.client_uri),
        policyUri: OAuthProviderImpl.validateStringField(clientMetadata.policy_uri),
        tosUri: OAuthProviderImpl.validateStringField(clientMetadata.tos_uri),
        jwksUri: OAuthProviderImpl.validateStringField(clientMetadata.jwks_uri),
        contacts: OAuthProviderImpl.validateStringArray(clientMetadata.contacts),
        grantTypes: OAuthProviderImpl.validateStringArray(clientMetadata.grant_types) || [
          GrantType.AUTHORIZATION_CODE,
          GrantType.REFRESH_TOKEN,
          ...(this.options.allowTokenExchangeGrant ? [GrantType.TOKEN_EXCHANGE] : []),
        ],
        responseTypes: OAuthProviderImpl.validateStringArray(clientMetadata.response_types) || ['code'],
        registrationDate: Math.floor(Date.now() / 1000),
        tokenEndpointAuthMethod: authMethod,
      };

      if (!isPublicClient && hashedSecret) {
        clientInfo.clientSecret = hashedSecret;
      }
    } catch (error) {
      return this.createErrorResponse(
        'invalid_client_metadata',
        error instanceof Error ? error.message : 'Invalid client metadata'
      );
    }

    await this.storage.put(`client:${clientId}`, JSON.stringify(clientInfo));

    const response: Record<string, any> = {
      client_id: clientInfo.clientId,
      redirect_uris: clientInfo.redirectUris,
      client_name: clientInfo.clientName,
      logo_uri: clientInfo.logoUri,
      client_uri: clientInfo.clientUri,
      policy_uri: clientInfo.policyUri,
      tos_uri: clientInfo.tosUri,
      jwks_uri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grant_types: clientInfo.grantTypes,
      response_types: clientInfo.responseTypes,
      token_endpoint_auth_method: clientInfo.tokenEndpointAuthMethod,
      registration_client_uri: `${this.options.clientRegistrationEndpoint}/${clientId}`,
      client_id_issued_at: clientInfo.registrationDate,
    };

    if (clientSecret) {
      response.client_secret = clientSecret;
      response.client_secret_expires_at = 0;
      response.client_secret_issued_at = clientInfo.registrationDate;
    }

    return new Response(JSON.stringify(response), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handles API requests by validating the access token and calling the API handler
   */
  private async handleApiRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

    // Get access token from Authorization header
    const authHeader = request.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return this.createErrorResponse('invalid_token', 'Missing or invalid access token', 401, {
        'WWW-Authenticate': this.buildWwwAuthenticateHeader(
          resourceMetadataUrl,
          'invalid_token',
          'Missing or invalid access token'
        ),
      });
    }

    const accessToken = authHeader.substring(7);
    const parts = accessToken.split(':');
    const isPossiblyInternalFormat = parts.length === 3;

    let tokenData: Token | null = null;
    let userId = '';
    let grantId = '';

    if (isPossiblyInternalFormat) {
      [userId, grantId] = parts;
      const id = await generateTokenId(accessToken);
      tokenData = await this.storageGetJson<Token>(`token:${userId}:${grantId}:${id}`);
    }

    if (!tokenData && !this.options.resolveExternalToken) {
      return this.createErrorResponse('invalid_token', 'Invalid access token', 401, {
        'WWW-Authenticate': this.buildWwwAuthenticateHeader(resourceMetadataUrl, 'invalid_token'),
      });
    }

    let props: any = undefined;

    if (tokenData) {
      const now = Math.floor(Date.now() / 1000);
      if (tokenData.expiresAt < now) {
        return this.createErrorResponse('invalid_token', 'Access token expired', 401, {
          'WWW-Authenticate': this.buildWwwAuthenticateHeader(resourceMetadataUrl, 'invalid_token'),
        });
      }

      // Validate audience
      if (tokenData.audience) {
        const requestUrl = new URL(request.url);
        const resourceServer = `${requestUrl.protocol}//${requestUrl.host}${requestUrl.pathname}`;
        const audiences = Array.isArray(tokenData.audience) ? tokenData.audience : [tokenData.audience];

        const matches = audiences.some((aud) => audienceMatches(resourceServer, aud));
        if (!matches) {
          return this.createErrorResponse('invalid_token', 'Token audience does not match resource server', 401, {
            'WWW-Authenticate': this.buildWwwAuthenticateHeader(
              resourceMetadataUrl,
              'invalid_token',
              'Invalid audience'
            ),
          });
        }
      }

      const encryptionKey = await unwrapKeyWithToken(accessToken, tokenData.wrappedEncryptionKey);
      props = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);
    } else if (this.options.resolveExternalToken) {
      const ext = await this.options.resolveExternalToken({ token: accessToken, request });

      if (!ext) {
        return this.createErrorResponse('invalid_token', 'Invalid access token', 401, {
          'WWW-Authenticate': this.buildWwwAuthenticateHeader(resourceMetadataUrl, 'invalid_token'),
        });
      }

      // Validate audience for external token
      if (ext.audience) {
        const requestUrl = new URL(request.url);
        const resourceServer = `${requestUrl.protocol}//${requestUrl.host}${requestUrl.pathname}`;
        const audiences = Array.isArray(ext.audience) ? ext.audience : [ext.audience];

        const matches = audiences.some((aud) => audienceMatches(resourceServer, aud));
        if (!matches) {
          return this.createErrorResponse('invalid_token', 'Token audience does not match resource server', 401, {
            'WWW-Authenticate': this.buildWwwAuthenticateHeader(
              resourceMetadataUrl,
              'invalid_token',
              'Invalid audience'
            ),
          });
        }
      }

      props = ext.props;
    }

    // Find the appropriate API handler for this URL
    const apiHandler = this.findApiHandlerForUrl(url);

    if (!apiHandler) {
      return this.createErrorResponse('invalid_request', 'No handler found for API route', 404);
    }

    // Call the API handler with props context
    return apiHandler.fetch(request, { props });
  }

  /**
   * Creates the helper methods object for OAuth operations
   */
  public createOAuthHelpers(): OAuthHelpersImpl {
    return new OAuthHelpersImpl(this);
  }

  /**
   * Saves a grant to storage with appropriate TTL based on expiration
   */
  private async saveGrantWithTTL(grantKey: string, grantData: Grant, now: number): Promise<void> {
    const options =
      grantData.expiresAt !== undefined ? { expirationTtl: Math.max(1, grantData.expiresAt - now) } : undefined;
    await this.storage.put(grantKey, JSON.stringify(grantData), options);
  }

  /**
   * Fetches client information from storage or via CIMD (Client ID Metadata Document)
   */
  async getClient(clientId: string): Promise<ClientInfo | null> {
    // Check if this is a CIMD (Client ID Metadata Document) URL
    if (this.isClientMetadataUrl(clientId)) {
      if (!this.options.clientIdMetadataDocumentEnabled) {
        const clientKey = `client:${clientId}`;
        return this.storageGetJson<ClientInfo>(clientKey);
      }

      const cimdCacheTtl = this.options.cimdCacheTtl ?? 0;

      // Check cache first
      if (cimdCacheTtl > 0) {
        const cacheKey = `cimd_cache:${clientId}`;
        const cached = await this.storageGetJson<{ clientInfo: ClientInfo; expiresAt: number }>(cacheKey);
        if (cached && cached.expiresAt > Math.floor(Date.now() / 1000)) {
          return cached.clientInfo;
        }
      }

      try {
        const clientInfo = await this.fetchClientMetadataDocument(clientId);

        // Store in cache (storage TTL is 2x cache TTL to allow stale-while-revalidate)
        if (cimdCacheTtl > 0) {
          const cacheEntry = {
            clientInfo,
            expiresAt: Math.floor(Date.now() / 1000) + cimdCacheTtl,
          };
          await this.storage.put(`cimd_cache:${clientId}`, JSON.stringify(cacheEntry), {
            expirationTtl: cimdCacheTtl * 2,
          });
        }

        return clientInfo;
      } catch (error) {
        console.warn(`CIMD fetch failed for ${clientId}:`, error instanceof Error ? error.message : error);

        // Serve stale cache on fetch failure
        if (cimdCacheTtl > 0) {
          const cacheKey = `cimd_cache:${clientId}`;
          const stale = await this.storageGetJson<{ clientInfo: ClientInfo }>(cacheKey);
          if (stale) return stale.clientInfo;
        }

        return null;
      }
    }

    // Standard storage lookup
    const clientKey = `client:${clientId}`;
    return this.storageGetJson<ClientInfo>(clientKey);
  }

  /**
   * Creates and stores an access token
   */
  private async createAccessToken(params: CreateAccessTokenOptions): Promise<string> {
    const { userId, grantId, clientId, scope, encryptedProps, encryptionKey, expiresIn, audience } = params;

    const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
    const accessToken = `${userId}:${grantId}:${accessTokenSecret}`;

    const now = Math.floor(Date.now() / 1000);
    const accessTokenId = await generateTokenId(accessToken);
    const accessTokenExpiresAt = now + expiresIn;

    const accessTokenWrappedKey = await wrapKeyWithToken(accessToken, encryptionKey);

    const accessTokenData: Token = {
      id: accessTokenId,
      grantId: grantId,
      userId: userId,
      createdAt: now,
      expiresAt: accessTokenExpiresAt,
      audience: audience,
      scope: scope,
      wrappedEncryptionKey: accessTokenWrappedKey,
      grant: {
        clientId: clientId,
        scope: scope,
        encryptedProps: encryptedProps,
      },
    };

    await this.storage.put(`token:${userId}:${grantId}:${accessTokenId}`, JSON.stringify(accessTokenData), {
      expirationTtl: expiresIn,
    });

    return accessToken;
  }

  /**
   * Downscopes requested scopes to only include those that are in the grant
   */
  private downscope(requestedScope: string | string[] | undefined, grantedScopes: string[]): string[] {
    if (!requestedScope) return grantedScopes;

    const requestedScopes: string[] =
      typeof requestedScope === 'string' ? requestedScope.split(' ').filter(Boolean) : requestedScope;

    return requestedScopes.filter((scope: string) => grantedScopes.includes(scope));
  }

  /**
   * Checks if a client_id is a CIMD URL (HTTPS with non-root path)
   */
  private isClientMetadataUrl(clientId: string): boolean {
    try {
      const url = new URL(clientId);
      return url.protocol === 'https:' && url.pathname !== '/';
    } catch {
      return false;
    }
  }

  /**
   * Maximum size for CIMD metadata documents (5KB per IETF spec recommendation)
   */
  private static readonly CIMD_MAX_SIZE_BYTES = 5 * 1024;

  /**
   * Request timeout for CIMD metadata fetches (10 seconds)
   */
  private static readonly CIMD_FETCH_TIMEOUT_MS = 10_000;

  /**
   * Allowed authentication methods for CIMD clients (per IETF spec)
   */
  private static readonly CIMD_ALLOWED_AUTH_METHODS = ['none', 'private_key_jwt'];

  private static validateStringField(field: unknown, fieldName?: string): string | undefined {
    if (field === undefined) return undefined;
    if (typeof field !== 'string') {
      throw new Error(
        fieldName ? `Invalid ${fieldName}: expected string, got ${typeof field}` : 'Field must be a string'
      );
    }
    return field;
  }

  private static validateStringArray(arr: unknown, fieldName?: string): string[] | undefined {
    if (arr === undefined) return undefined;
    if (!Array.isArray(arr)) {
      throw new Error(fieldName ? `Invalid ${fieldName}: expected array, got ${typeof arr}` : 'Field must be an array');
    }
    if (!arr.every((item) => typeof item === 'string')) {
      throw new Error(
        fieldName ? `Invalid ${fieldName}: array must contain only strings` : 'All array elements must be strings'
      );
    }
    return arr;
  }

  /**
   * Fetches and validates a Client ID Metadata Document from the given URL
   */
  private async fetchClientMetadataDocument(metadataUrl: string): Promise<ClientInfo> {
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), OAuthProviderImpl.CIMD_FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(metadataUrl, {
        headers: { Accept: 'application/json' },
        signal: abortController.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Failed to fetch client metadata: HTTP ${response.status}`);
      }

      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > OAuthProviderImpl.CIMD_MAX_SIZE_BYTES) {
        throw new Error(
          `Client metadata exceeds size limit: ${contentLength} bytes (max ${OAuthProviderImpl.CIMD_MAX_SIZE_BYTES})`
        );
      }

      const rawMetadata = await this.readJsonWithSizeLimit(response, OAuthProviderImpl.CIMD_MAX_SIZE_BYTES);

      const clientId = OAuthProviderImpl.validateStringField(rawMetadata.client_id, 'client_id');
      const redirectUris = OAuthProviderImpl.validateStringArray(rawMetadata.redirect_uris, 'redirect_uris');
      const tokenEndpointAuthMethod = OAuthProviderImpl.validateStringField(
        rawMetadata.token_endpoint_auth_method,
        'token_endpoint_auth_method'
      );

      if (clientId !== metadataUrl) {
        throw new Error(`client_id "${clientId}" does not match metadata URL "${metadataUrl}"`);
      }

      if (!redirectUris || redirectUris.length === 0) {
        throw new Error('redirect_uris is required and must not be empty');
      }

      if (tokenEndpointAuthMethod && !OAuthProviderImpl.CIMD_ALLOWED_AUTH_METHODS.includes(tokenEndpointAuthMethod)) {
        throw new Error(
          `token_endpoint_auth_method "${tokenEndpointAuthMethod}" is not allowed for CIMD clients. ` +
            `Allowed methods: ${OAuthProviderImpl.CIMD_ALLOWED_AUTH_METHODS.join(', ')}`
        );
      }

      return {
        clientId,
        redirectUris,
        clientName: OAuthProviderImpl.validateStringField(rawMetadata.client_name, 'client_name'),
        clientUri: OAuthProviderImpl.validateStringField(rawMetadata.client_uri, 'client_uri'),
        logoUri: OAuthProviderImpl.validateStringField(rawMetadata.logo_uri, 'logo_uri'),
        policyUri: OAuthProviderImpl.validateStringField(rawMetadata.policy_uri, 'policy_uri'),
        tosUri: OAuthProviderImpl.validateStringField(rawMetadata.tos_uri, 'tos_uri'),
        jwksUri: OAuthProviderImpl.validateStringField(rawMetadata.jwks_uri, 'jwks_uri'),
        contacts: OAuthProviderImpl.validateStringArray(rawMetadata.contacts, 'contacts'),
        grantTypes: OAuthProviderImpl.validateStringArray(rawMetadata.grant_types, 'grant_types') || [
          'authorization_code',
        ],
        responseTypes: OAuthProviderImpl.validateStringArray(rawMetadata.response_types, 'response_types') || ['code'],
        tokenEndpointAuthMethod: tokenEndpointAuthMethod || 'none',
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Reads JSON from a response with a size limit to prevent DoS attacks.
   */
  private async readJsonWithSizeLimit(response: Response, maxBytes: number): Promise<Record<string, unknown>> {
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('Response body is null');
    }

    const chunks: Uint8Array[] = [];
    let totalSize = 0;

    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      if (value) {
        totalSize += value.length;

        if (totalSize > maxBytes) {
          await reader.cancel();
          throw new Error(`Response exceeded size limit of ${maxBytes} bytes`);
        }

        chunks.push(value);
      }
    }

    const allChunks = new Uint8Array(totalSize);
    let position = 0;
    for (const chunk of chunks) {
      allChunks.set(chunk, position);
      position += chunk.length;
    }

    const text = new TextDecoder().decode(allChunks);
    return JSON.parse(text);
  }

  /**
   * Builds a WWW-Authenticate header value with resource_metadata per RFC 9728 §5.1
   */
  private buildWwwAuthenticateHeader(resourceMetadataUrl: string, error: string, errorDescription?: string): string {
    let header = `Bearer realm="OAuth", resource_metadata="${resourceMetadataUrl}", error="${error}"`;
    if (errorDescription) {
      header += `, error_description="${errorDescription}"`;
    }
    return header;
  }

  /**
   * Helper function to create OAuth error responses
   */
  private createErrorResponse(
    code: string,
    description: string,
    status: number = 400,
    headers: Record<string, string> = {}
  ): Response {
    const customErrorResponse = this.options.onError?.({ code, description, status, headers });
    if (customErrorResponse) return customErrorResponse;

    const body = JSON.stringify({
      error: code,
      error_description: description,
    });

    return new Response(body, {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    });
  }
}

// Constants
class OAuthError extends Error {
  constructor(
    public code: string,
    message: string
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60;

const TOKEN_LENGTH = 32;

// Helper Functions

function validateResourceUri(uri: string): boolean {
  if (!uri || typeof uri !== 'string') {
    return false;
  }

  try {
    const parsed = new URL(uri);

    if (!parsed.protocol) {
      return false;
    }

    if (parsed.hash) {
      return false;
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

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

function parseResourceParameter(value: string | string[] | undefined): string | string[] | undefined {
  if (!value) {
    return undefined;
  }

  const uris = Array.isArray(value) ? value : [value];
  for (const uri of uris) {
    if (typeof uri !== 'string' || !validateResourceUri(uri)) {
      return undefined;
    }
  }

  return value;
}

async function hashSecret(secret: string): Promise<string> {
  return generateTokenId(secret);
}

function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let result = '';
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += characters.charAt(values[i] % characters.length);
  }
  return result;
}

async function generateTokenId(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);

  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
}

function validateRedirectUriScheme(redirectUri: string): void {
  const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'mailto:', 'blob:'];

  const normalized = redirectUri.trim();

  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
      throw new Error('Invalid redirect URI');
    }
  }

  const colonIndex = normalized.indexOf(':');
  if (colonIndex === -1) {
    throw new Error('Invalid redirect URI');
  }

  const scheme = normalized.substring(0, colonIndex + 1).toLowerCase();

  for (const dangerousScheme of dangerousSchemes) {
    if (scheme === dangerousScheme) {
      throw new Error('Invalid redirect URI');
    }
  }
}

function isLoopbackUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    const host = url.hostname;
    if (host.match(/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
      return true;
    }
    if (host === '::1' || host === '[::1]') {
      return true;
    }
    if (host.toLowerCase() === 'localhost') {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isValidRedirectUri(requestUri: string, registeredUris: string[]): boolean {
  return registeredUris.some((registered) => {
    if (isLoopbackUri(requestUri) && isLoopbackUri(registered)) {
      try {
        const reqUrl = new URL(requestUri);
        const regUrl = new URL(registered);
        return (
          reqUrl.protocol === regUrl.protocol &&
          reqUrl.hostname === regUrl.hostname &&
          reqUrl.pathname === regUrl.pathname &&
          reqUrl.search === regUrl.search
        );
      } catch {
        return false;
      }
    }
    return requestUri === registered;
  });
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

async function encryptProps(data: any): Promise<{ encryptedData: string; key: CryptoKey }> {
  // @ts-ignore
  const key: CryptoKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = new Uint8Array(12);

  const jsonData = JSON.stringify(data);
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(jsonData);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encodedData
  );

  return {
    encryptedData: arrayBufferToBase64(encryptedBuffer),
    key,
  };
}

async function decryptProps(key: CryptoKey, encryptedData: string): Promise<any> {
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);

  const iv = new Uint8Array(12);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encryptedBuffer
  );

  const decoder = new TextDecoder();
  const jsonData = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonData);
}

const WRAPPING_KEY_HMAC_KEY = new Uint8Array([
  0x22, 0x7e, 0x26, 0x86, 0x8d, 0xf1, 0xe1, 0x6d, 0x80, 0x70, 0xea, 0x17, 0x97, 0x5b, 0x47, 0xa6, 0x82, 0x18, 0xfa,
  0x87, 0x28, 0xae, 0xde, 0x85, 0xb5, 0x1d, 0x4a, 0xd9, 0x96, 0xca, 0xca, 0x43,
]);

async function deriveKeyFromToken(tokenStr: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    WRAPPING_KEY_HMAC_KEY,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const hmacResult = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(tokenStr));

  return await crypto.subtle.importKey(
    'raw',
    hmacResult,
    { name: 'AES-KW' },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function wrapKeyWithToken(tokenStr: string, keyToWrap: CryptoKey): Promise<string> {
  const wrappingKey = await deriveKeyFromToken(tokenStr);
  const wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' });
  return arrayBufferToBase64(wrappedKeyBuffer);
}

async function unwrapKeyWithToken(tokenStr: string, wrappedKeyBase64: string): Promise<CryptoKey> {
  const wrappingKey = await deriveKeyFromToken(tokenStr);
  const wrappedKeyBuffer = base64ToArrayBuffer(wrappedKeyBase64);

  return await crypto.subtle.unwrapKey(
    'raw',
    wrappedKeyBuffer,
    wrappingKey,
    { name: 'AES-KW' },
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Class that implements the OAuth helper methods
 */
class OAuthHelpersImpl implements OAuthHelpers {
  private storage: StorageAdapter;
  private provider: OAuthProviderImpl;

  constructor(provider: OAuthProviderImpl) {
    this.storage = provider.storage;
    this.provider = provider;
  }

  async parseAuthRequest(request: Request): Promise<AuthRequest> {
    const url = new URL(request.url);
    const responseType = url.searchParams.get('response_type') || '';
    const clientId = url.searchParams.get('client_id') || '';
    const redirectUri = url.searchParams.get('redirect_uri') || '';
    const scope = (url.searchParams.get('scope') || '').split(' ').filter(Boolean);
    const state = url.searchParams.get('state') || '';
    const codeChallenge = url.searchParams.get('code_challenge') || undefined;
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') || 'plain';
    const resourceParams = url.searchParams.getAll('resource');
    const resourceParam =
      resourceParams.length > 0 ? (resourceParams.length === 1 ? resourceParams[0] : resourceParams) : undefined;

    validateRedirectUriScheme(redirectUri);

    const resource = parseResourceParameter(resourceParam);
    if (resourceParam && !resource) {
      throw new Error('The resource parameter must be a valid absolute URI without a fragment');
    }

    if (responseType === 'token' && !this.provider.options.allowImplicitFlow) {
      throw new Error('The implicit grant flow is not enabled for this provider');
    }

    if (codeChallengeMethod === 'plain' && !this.provider.options.allowPlainPKCE) {
      throw new Error('The plain PKCE method is not allowed. Use S256 instead.');
    }

    if (clientId) {
      const clientInfo = await this.lookupClient(clientId);

      if (!clientInfo) {
        throw new Error(`Invalid client. The clientId provided does not match to this client.`);
      }
      if (clientInfo && redirectUri) {
        if (!isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
          throw new Error(
            `Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.`
          );
        }
      }
    }

    return {
      responseType,
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod,
      resource,
    };
  }

  async lookupClient(clientId: string): Promise<ClientInfo | null> {
    return await this.provider.getClient(clientId);
  }

  async completeAuthorization(options: CompleteAuthorizationOptions): Promise<{ redirectTo: string }> {
    const { clientId, redirectUri } = options.request;

    if (!clientId || !redirectUri) {
      throw new Error('Client ID and Redirect URI are required in the authorization request.');
    }

    const clientInfo = await this.lookupClient(clientId);
    if (!clientInfo || !isValidRedirectUri(redirectUri, clientInfo.redirectUris)) {
      throw new Error(
        'Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.'
      );
    }

    // Collect existing grants for revocation
    let grantsToRevoke: string[] = [];
    if (options.revokeExistingGrants !== false) {
      let cursor: string | undefined;
      do {
        const page = await this.listUserGrants(options.userId, { cursor });
        for (const grant of page.items) {
          if (grant.clientId === clientId) {
            grantsToRevoke.push(grant.id);
          }
        }
        cursor = page.cursor;
      } while (cursor);
    }

    const grantId = generateRandomString(16);
    const { encryptedData, key: encryptionKey } = await encryptProps(options.props);
    const now = Math.floor(Date.now() / 1000);

    // Check if this is an implicit flow request (response_type=token)
    if (options.request.responseType === 'token') {
      const accessTokenSecret = generateRandomString(TOKEN_LENGTH);
      const accessToken = `${options.userId}:${grantId}:${accessTokenSecret}`;
      const accessTokenId = await generateTokenId(accessToken);

      const accessTokenTTL = this.provider.options.accessTokenTTL || DEFAULT_ACCESS_TOKEN_TTL;
      const accessTokenExpiresAt = now + accessTokenTTL;

      const accessTokenWrappedKey = await wrapKeyWithToken(accessToken, encryptionKey);

      const audience = parseResourceParameter(options.request.resource);
      if (options.request.resource && !audience) {
        throw new Error('The resource parameter must be a valid absolute URI without a fragment');
      }

      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
        resource: options.request.resource,
      };

      const grantKey = `grant:${options.userId}:${grantId}`;
      await this.storage.put(grantKey, JSON.stringify(grant));

      const accessTokenData: Token = {
        id: accessTokenId,
        grantId: grantId,
        userId: options.userId,
        createdAt: now,
        expiresAt: accessTokenExpiresAt,
        audience: audience,
        scope: options.scope,
        wrappedEncryptionKey: accessTokenWrappedKey,
        grant: {
          clientId: options.request.clientId,
          scope: options.scope,
          encryptedProps: encryptedData,
        },
      };

      await this.storage.put(
        `token:${options.userId}:${grantId}:${accessTokenId}`,
        JSON.stringify(accessTokenData),
        { expirationTtl: accessTokenTTL }
      );

      const redirectUrl = new URL(options.request.redirectUri);
      const fragment = new URLSearchParams();
      fragment.set('access_token', accessToken);
      fragment.set('token_type', 'bearer');
      fragment.set('expires_in', accessTokenTTL.toString());
      fragment.set('scope', options.scope.join(' '));

      if (options.request.state) {
        fragment.set('state', options.request.state);
      }

      redirectUrl.hash = fragment.toString();

      try {
        await Promise.allSettled(grantsToRevoke.map((oldGrantId) => this.revokeGrant(oldGrantId, options.userId)));
      } catch {
        // Best-effort revocation
      }

      return { redirectTo: redirectUrl.toString() };
    } else {
      // Standard authorization code flow
      const authCodeSecret = generateRandomString(32);
      const authCode = `${options.userId}:${grantId}:${authCodeSecret}`;
      const authCodeId = await hashSecret(authCode);
      const authCodeWrappedKey = await wrapKeyWithToken(authCode, encryptionKey);

      const grant: Grant = {
        id: grantId,
        clientId: options.request.clientId,
        userId: options.userId,
        scope: options.scope,
        metadata: options.metadata,
        encryptedProps: encryptedData,
        createdAt: now,
        authCodeId: authCodeId,
        authCodeWrappedKey: authCodeWrappedKey,
        codeChallenge: options.request.codeChallenge,
        codeChallengeMethod: options.request.codeChallengeMethod,
        resource: options.request.resource,
      };

      const grantKey = `grant:${options.userId}:${grantId}`;
      const codeExpiresIn = 600; // 10 minutes
      await this.storage.put(grantKey, JSON.stringify(grant), { expirationTtl: codeExpiresIn });

      const redirectUrl = new URL(options.request.redirectUri);
      redirectUrl.searchParams.set('code', authCode);
      if (options.request.state) {
        redirectUrl.searchParams.set('state', options.request.state);
      }

      try {
        await Promise.allSettled(grantsToRevoke.map((oldGrantId) => this.revokeGrant(oldGrantId, options.userId)));
      } catch {
        // Best-effort revocation
      }

      return { redirectTo: redirectUrl.toString() };
    }
  }

  async createClient(clientInfo: Partial<ClientInfo>): Promise<ClientInfo> {
    const clientId = generateRandomString(16);

    const tokenEndpointAuthMethod = clientInfo.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = tokenEndpointAuthMethod === 'none';

    const newClient: ClientInfo = {
      clientId,
      redirectUris: clientInfo.redirectUris || [],
      clientName: clientInfo.clientName,
      logoUri: clientInfo.logoUri,
      clientUri: clientInfo.clientUri,
      policyUri: clientInfo.policyUri,
      tosUri: clientInfo.tosUri,
      jwksUri: clientInfo.jwksUri,
      contacts: clientInfo.contacts,
      grantTypes: clientInfo.grantTypes || [
        GrantType.AUTHORIZATION_CODE,
        GrantType.REFRESH_TOKEN,
        ...(this.provider.options.allowTokenExchangeGrant ? [GrantType.TOKEN_EXCHANGE] : []),
      ],
      responseTypes: clientInfo.responseTypes || ['code'],
      registrationDate: Math.floor(Date.now() / 1000),
      tokenEndpointAuthMethod,
    };

    for (const uri of newClient.redirectUris) {
      validateRedirectUriScheme(uri);
    }

    let clientSecret: string | undefined;
    if (!isPublicClient) {
      clientSecret = generateRandomString(32);
      newClient.clientSecret = await hashSecret(clientSecret);
    }

    await this.storage.put(`client:${clientId}`, JSON.stringify(newClient));

    const clientResponse = { ...newClient };

    if (!isPublicClient && clientSecret) {
      clientResponse.clientSecret = clientSecret;
    }

    return clientResponse;
  }

  async listClients(options?: ListOptions): Promise<ListResult<ClientInfo>> {
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: 'client:',
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    const response = await this.storage.list(listOptions);

    const clients: ClientInfo[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const clientId = key.name.substring('client:'.length);
      const client = await this.provider.getClient(clientId);
      if (client) {
        clients.push(client);
      }
    });

    await Promise.all(promises);

    return {
      items: clients,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  async updateClient(clientId: string, updates: Partial<ClientInfo>): Promise<ClientInfo | null> {
    const client = await this.provider.getClient(clientId);
    if (!client) {
      return null;
    }

    let authMethod = updates.tokenEndpointAuthMethod || client.tokenEndpointAuthMethod || 'client_secret_basic';
    const isPublicClient = authMethod === 'none';

    let secretToStore = client.clientSecret;
    let originalSecret: string | undefined = undefined;

    if (isPublicClient) {
      secretToStore = undefined;
    } else if (updates.clientSecret) {
      originalSecret = updates.clientSecret;
      secretToStore = await hashSecret(updates.clientSecret);
    }

    const updatedClient: ClientInfo = {
      ...client,
      ...updates,
      clientId: client.clientId,
      tokenEndpointAuthMethod: authMethod,
    };

    if (!isPublicClient && secretToStore) {
      updatedClient.clientSecret = secretToStore;
    } else {
      delete updatedClient.clientSecret;
    }

    await this.storage.put(`client:${clientId}`, JSON.stringify(updatedClient));

    const response = { ...updatedClient };

    if (!isPublicClient && originalSecret) {
      response.clientSecret = originalSecret;
    }

    return response;
  }

  async deleteClient(clientId: string): Promise<void> {
    await this.storage.delete(`client:${clientId}`);
  }

  async listUserGrants(userId: string, options?: ListOptions): Promise<ListResult<GrantSummary>> {
    const listOptions: { limit?: number; cursor?: string; prefix: string } = {
      prefix: `grant:${userId}:`,
    };

    if (options?.limit !== undefined) {
      listOptions.limit = options.limit;
    }

    if (options?.cursor !== undefined) {
      listOptions.cursor = options.cursor;
    }

    const response = await this.storage.list(listOptions);

    const grantSummaries: GrantSummary[] = [];
    const promises = response.keys.map(async (key: { name: string }) => {
      const raw = await this.storage.get(key.name);
      const grantData: Grant | null = raw ? JSON.parse(raw) : null;
      if (grantData) {
        const summary: GrantSummary = {
          id: grantData.id,
          clientId: grantData.clientId,
          userId: grantData.userId,
          scope: grantData.scope,
          metadata: grantData.metadata,
          createdAt: grantData.createdAt,
          expiresAt: grantData.expiresAt,
        };
        grantSummaries.push(summary);
      }
    });

    await Promise.all(promises);

    return {
      items: grantSummaries,
      cursor: response.list_complete ? undefined : response.cursor,
    };
  }

  async revokeGrant(grantId: string, userId: string): Promise<void> {
    const grantKey = `grant:${userId}:${grantId}`;
    const tokenPrefix = `token:${userId}:${grantId}:`;

    let cursor: string | undefined;
    let allTokensDeleted = false;

    while (!allTokensDeleted) {
      const listOptions: { prefix: string; cursor?: string } = {
        prefix: tokenPrefix,
      };

      if (cursor) {
        listOptions.cursor = cursor;
      }

      const result = await this.storage.list(listOptions);

      if (result.keys.length > 0) {
        await Promise.all(
          result.keys.map((key: { name: string }) => {
            return this.storage.delete(key.name);
          })
        );
      }

      if (result.list_complete) {
        allTokensDeleted = true;
      } else {
        cursor = result.cursor;
      }
    }

    await this.storage.delete(grantKey);
  }

  async unwrapToken<T = any>(token: string): Promise<TokenSummary<T> | null> {
    return await this.provider.unwrapToken(token);
  }

  async exchangeToken(options: ExchangeTokenOptions): Promise<TokenResponse> {
    const tokenSummary = await this.unwrapToken(options.subjectToken);
    if (!tokenSummary) {
      throw new Error('Invalid or expired subject token');
    }

    const clientInfo = await this.lookupClient(tokenSummary.grant.clientId);
    if (!clientInfo) {
      throw new Error('Client not found');
    }

    return await this.provider.exchangeToken(
      options.subjectToken,
      options.scope,
      options.aud,
      options.expiresIn,
      clientInfo,
      options.actorToken,
      options.actorTokenType
    );
  }
}

/**
 * Default export of the OAuth provider
 */
export default OAuthProvider;
