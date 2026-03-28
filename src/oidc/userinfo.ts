/** User info claims from OIDC UserInfo endpoint */
export interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  [key: string]: unknown;
}

/** Options for fetching user info */
export interface FetchUserInfoOptions {
  /** Custom fetch function (for testing) */
  fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
}

/**
 * Fetch user info from an OIDC UserInfo endpoint.
 */
export async function fetchUserInfo(
  accessToken: string,
  userInfoEndpoint: string,
  options?: FetchUserInfoOptions
): Promise<UserInfo> {
  const fetchFn = options?.fetch ?? globalThis.fetch;
  const timeoutMs = options?.timeoutMs ?? 10000;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchFn(userInfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error(`UserInfo request timed out`);
    }
    throw new Error(`UserInfo request failed: ${error instanceof Error ? error.message : error}`);
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`UserInfo request failed: HTTP ${response.status}`);
  }

  let userInfo: UserInfo;
  try {
    userInfo = (await response.json()) as UserInfo;
  } catch {
    throw new Error('UserInfo response is not valid JSON');
  }

  if (!userInfo.sub) {
    throw new Error('UserInfo response missing required field: sub');
  }

  return userInfo;
}
