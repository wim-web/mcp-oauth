/**
 * OIDC Provider Configuration (OpenID Connect Discovery 1.0)
 */
export interface OidcConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  id_token_signing_alg_values_supported?: string[];
  [key: string]: unknown;
}

/** Options for OIDC discovery */
export interface DiscoverOptions {
  /** Custom fetch function (for testing or custom HTTP) */
  fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
}

/**
 * Fetch and validate the OIDC configuration for an issuer.
 * Constructs the well-known URL from the issuer per OpenID Connect Discovery 1.0 Section 4.
 */
export async function discoverOIDC(issuer: string, options?: DiscoverOptions): Promise<OidcConfiguration> {
  const fetchFn = options?.fetch ?? globalThis.fetch;
  const timeoutMs = options?.timeoutMs ?? 10000;

  // Normalize issuer: strip trailing slash
  const normalizedIssuer = issuer.replace(/\/+$/, '');
  const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchFn(discoveryUrl, { signal: controller.signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error(`OIDC discovery timed out for ${normalizedIssuer}`);
    }
    throw new Error(`OIDC discovery failed for ${normalizedIssuer}: ${error instanceof Error ? error.message : error}`);
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`OIDC discovery failed for ${normalizedIssuer}: HTTP ${response.status}`);
  }

  let config: OidcConfiguration;
  try {
    config = (await response.json()) as OidcConfiguration;
  } catch {
    throw new Error(`OIDC discovery failed for ${normalizedIssuer}: invalid JSON`);
  }

  // Validate required fields per OpenID Connect Discovery 1.0 Section 3
  if (!config.issuer) {
    throw new Error('OIDC configuration missing required field: issuer');
  }
  if (config.issuer !== normalizedIssuer) {
    throw new Error(`OIDC issuer mismatch: expected ${normalizedIssuer}, got ${config.issuer}`);
  }
  if (!config.authorization_endpoint) {
    throw new Error('OIDC configuration missing required field: authorization_endpoint');
  }
  if (!config.token_endpoint) {
    throw new Error('OIDC configuration missing required field: token_endpoint');
  }
  if (!config.jwks_uri) {
    throw new Error('OIDC configuration missing required field: jwks_uri');
  }
  if (!config.response_types_supported || !Array.isArray(config.response_types_supported)) {
    throw new Error('OIDC configuration missing required field: response_types_supported');
  }

  return config;
}
