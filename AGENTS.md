# AGENTS.md

## Repo intent

This repo is a fork of `@cloudflare/workers-oauth-provider`. Keep the fork focused on removing Cloudflare Workers dependencies so the library runs on standard fetch platforms such as Next.js and Node.js.

## Critical rule: `src/oauth-provider.ts`

`src/oauth-provider.ts` is the upstream-ported core file. Do not add features, refactor logic, or widen interfaces in this file.

Allowed changes in `src/oauth-provider.ts`:

- Remove or replace Cloudflare-specific APIs.
- Fix imports and types required for the platform migration.
- Apply formatting-only changes.

New functionality belongs in fork-specific modules such as `src/next.ts`, `src/oidc/`, or new files.

Keep upstream types such as `Grant`, `ResolveExternalTokenResult`, and `TokenSummary` unchanged unless the upstream-compatible port requires otherwise.

## OAuth and MCP changes

When changing OAuth behavior, check the latest published MCP specification first:

- Spec: https://modelcontextprotocol.io/specification/2025-11-25
- Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

For MCP-related OAuth behavior, the published MCP spec takes precedence over local assumptions.

## Required checks

- Run `npm run check` before considering work done.
- Add or update tests for behavior changes.
- Add a changeset for public API changes and user-visible bug fixes.
- Do not hand-edit generated files such as `dist/` or `package-lock.json`.

## Coding guardrails

- Preserve backwards compatibility for the supported handler patterns.
- Document public APIs with JSDoc.
- Avoid `any` unless there is a specific justification.

## Security guardrails

This is a security-critical OAuth library.

- Never store unhashed tokens or secrets.
- Never bypass constructor validation.
- Treat storage schema changes, token handling, and redirect validation as high-risk areas.

## Ask first

- Adding new runtime dependencies.
- Changing the storage schema.
- Modifying OAuth endpoints or flows.
- Adding new feature flags.

## Reference docs

Use these human-oriented docs for detail instead of expanding this file:

- `README.md` for package usage and standards.
- `CONTRIBUTING.md` for development workflow.
- `SECURITY.md` for disclosure policy.
- `storage-schema.md` for persistence details.
