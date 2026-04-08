---
'@0x-wim/mcp-oauth': minor
---

Merge upstream RFC 9728 path-aware protected resource metadata support, including path-suffixed
`resource_metadata` URLs in `WWW-Authenticate` headers and a new `resourceMatchOriginOnly`
migration option for origin-only grants.

Also normalize Next.js App Router requests to their public forwarded URL before
calling the provider, so standalone and Docker deployments use the external
host for OAuth metadata and audience checks.
