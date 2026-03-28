# ADR-001: Fork from cloudflare/workers-oauth-provider

## Status

Accepted

## Context

MCP (Model Context Protocol) の OAuth 2.1 認可機能を提供するために、既存の実装をベースにしたかった。`cloudflare/workers-oauth-provider` は機能的に充実しているが、Cloudflare Workers に強く依存しており、他のプラットフォームでは使えない。

## Decision

`cloudflare/workers-oauth-provider` を fork し、プラットフォーム非依存の単一パッケージ `mcp-oauth` に変換する。サブパスエクスポートで `/next`、`/oidc` を提供する。

### パッケージ構成

| エクスポート | 説明 |
|---|---|
| `mcp-oauth` | プラットフォーム非依存の OAuth 2.1 プロバイダ |
| `mcp-oauth/next` | Next.js App Router ラッパー |
| `mcp-oauth/oidc` | OIDC Discovery / ID Token 検証 / UserInfo ヘルパー |

### 実装フェーズ

**Phase 1: Cloudflare 依存除去**
- `cloudflare:workers` / `ExecutionContext` / `WorkerEntrypoint` / `Env` ジェネリックを全て除去
- `StorageAdapter` インターフェースと `MemoryStore` 実装を追加
- `OAuthProvider.fetch()` は `(request: Request)` のみ受け取る
- `OAuthProvider` が `OAuthHelpers` メソッドを直接公開 (`env.OAUTH_PROVIDER` 不要)
- Cloudflare 固有の SSRF チェック除去

**Phase 2: Next.js ラッパー (`mcp-oauth/next`)**
- `createOAuthHandlers(provider)` — App Router catch-all route 用ハンドラ生成
- `getAuth<T>(provider, request)` — Bearer トークン検証ユーティリティ

**Phase 3: OIDC ヘルパー (`mcp-oauth/oidc`)**
- `discoverOIDC(issuer)` — OpenID Connect Discovery 1.0
- `verifyIdToken(token, options)` — RS256/ES256 署名検証 (Web Crypto API のみ)
- `fetchUserInfo(accessToken, endpoint)` — UserInfo エンドポイント

**Phase 4: コア機能追加**
- `refreshTokenGracePeriod` — 前リフレッシュトークンの有効期間制限
- `revokeGrantOnRefreshTokenReplay` — リプレイ検知時グラント失効
- `cimdCacheTtl` — CIMD キャッシュ (StorageAdapter 経由、stale-while-revalidate)
- `actorToken` / `actorTokenType` — RFC 8693 actor_token サポート
- `may_act` クレーム検証

## Consequences

### Positive
- `src/oauth-provider.ts` を root に保持し、upstream との diff が追いやすい
- 単一パッケージのためモノレポ不要、管理がシンプル
- Web 標準 API (Request/Response/Web Crypto) のみに依存するため、どのランタイムでも動く

### Negative
- upstream の変更を手動で追従する必要がある
- Cloudflare Workers 固有の最適化 (Durable Objects 等) は使えない

## 設計方針

- upstream との差分を最小限に保つ
- PImpl パターンで RPC 安全性を確保
- AES-GCM 暗号化、AES-KW キーラッピング
- HMAC-SHA256 でトークンからキーを導出
- トークン形式: `{userId}:{grantId}:{randomSecret}`
- ストレージキーパターン: `client:{id}`, `grant:{userId}:{grantId}`, `token:{userId}:{grantId}:{tokenId}`

## 準拠 RFC

- RFC 8414 (OAuth Server Metadata)
- RFC 9728 (Protected Resource Metadata)
- RFC 8707 (Resource Indicators)
- RFC 7591 (Dynamic Client Registration)
- RFC 8693 (Token Exchange)
- RFC 7009 (Token Revocation)
- RFC 8252 (Native Apps / Loopback)
