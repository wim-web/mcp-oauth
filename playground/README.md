# Playground

`mcp-oauth` の動作確認用デモ。OAuth 2.1 + PKCE フロー、Next.js 統合、MCP サーバーを試せる。

## 起動

### 推奨: リポジトリルートから起動

```bash
npm install
npm run dev
```

`npm run dev` は次の 2 つを並列で起動する。

- ルートの `tsdown --watch`
- Playground の `next dev --port 3456`

Playground はルートの `dist/` を直接参照しているので、`src/` 配下を修正すると再ビルドされ、そのまま Playground に反映される。

ブラウザでは http://localhost:3456 を開く。

### Playground だけ起動する場合

```bash
cd playground
npm install
npm run dev -- --port 3456
```

この起動方法では Next.js 側の変更監視だけが動く。ルートの `src/` を編集して反映させたい場合は、別ターミナルでリポジトリルートから `npm run build:watch` も起動すること。

`3456` が使用中なら既存プロセスを止めるか、別ポートを指定する。その場合は Inspector の URL も同じポートに合わせる。

## Web UI (OAuth + MCP)

1. **Register Client** — OAuth クライアントを動的登録
2. **Login (OAuth)** — PKCE 付き認可フロー。認可画面で Approve を押す
3. **Call /api/me** — Bearer トークンでユーザー情報を取得
4. **Connect to MCP Server** — MCP セッションを確立
5. ドロップダウンから **hello** / **whoami** を選んで **Call**

サーバー再起動すると MemoryStore がリセットされるので **Reset** → **Register Client** からやり直す。

## エンドポイント一覧

| パス | 説明 |
|---|---|
| `/` | Playground Web UI |
| `/.well-known/oauth-authorization-server` | OAuth メタデータ (RFC 8414) |
| `/oauth/register` | クライアント動的登録 (RFC 7591) |
| `/oauth/authorize` | 認可エンドポイント |
| `/oauth/token` | トークンエンドポイント |
| `/mcp` | MCP エンドポイント (OAuth 認証必須) |
| `/api/me` | ユーザー情報 API (Bearer トークン) |

## MCP Inspector

```bash
npm run inspector
```

`3456` 以外で起動している場合は、代わりに次を使う。

```bash
npx @modelcontextprotocol/inspector --url http://localhost:<port>/mcp
```

ブラウザが開いたら:

1. **Transport Type** が `Streamable HTTP` になっていることを確認
2. **URL** に `http://localhost:3456/mcp` が入っている状態で **Connect** を押す
3. OAuth 認可画面にリダイレクトされるので **Approve** を押す
4. 接続完了後、**Tools** タブ → **List Tools** で hello / whoami が表示される
5. ツール名をクリック → 引数を入力 → **Run Tool**

それ以外の入力欄（Headers, Auth, Config 等）は無視してOK。

## スクリプト

```bash
# OAuth フロー (provider.fetch 直接呼び出し)
node demo.mjs

# MCP サーバー単体起動 (ポート 9876)
node mcp-server.mjs
```
