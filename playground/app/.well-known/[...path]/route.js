import { createOAuthHandlers } from '../../../lib/mcp-oauth-next.js';
import { provider } from '../../../lib/provider.js';

export const { GET, POST, OPTIONS } = createOAuthHandlers(provider);
