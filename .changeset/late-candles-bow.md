---
'@0x-wim/mcp-oauth': patch
---

Normalize Next.js App Router request URLs from forwarded headers before
calling the OAuth provider, so standalone and Docker deployments use the
public host for OAuth metadata and audience checks.
