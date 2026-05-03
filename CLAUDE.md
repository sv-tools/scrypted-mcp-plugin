# scrypted-mcp

Scrypted plugin that exposes a Streamable HTTP Model Context Protocol endpoint. AI clients (Claude Desktop, Claude Code, etc.) authenticate via OAuth backed by Scrypted user accounts and call MCP tools to inspect logs, manage plugins, and query devices on the same Scrypted server.

## Commands

```bash
npm run build       # scrypted-webpack → out/main.nodejs.js (+ plugin.zip)
npm run fmt         # prettier --write
npm run fmt:check   # CI gate
npm run lint        # eslint
npm run lint:fix
npm run scrypted-deploy-debug   # build + push to a running Scrypted server (see SDK docs)
```

CI runs `fmt:check`, `lint`, `build` on every push/PR (`.github/workflows/ci.yml`). `publish.yml` runs on `v*` tags and pushes to npm.

## Architecture

The plugin is one process inside Scrypted. `src/main.ts` declares `ScryptedMcpPlugin extends ScryptedDeviceBase implements HttpRequestHandler` and registers the full MCP tool surface on a per-session `McpServer`. Inbound HTTP requests are dispatched in `onRequest`:

1. `OAuthService.handle()` claims `/authorize`, `/token`, `/register`, and the four `.well-known/*` documents (`oauth-protected-resource`, `oauth-authorization-server`, `openid-configuration`, `jwks.json`). If it returns true, the response is already populated.
2. Otherwise, if the path resolves to `/mcp`, we verify the Bearer JWT, look up (or create) a `WebStandardStreamableHTTPServerTransport` keyed by the `Mcp-Session-Id` header, bridge the Scrypted request to a Web-standard `Request`, and forward.
3. Anything else returns 404.

`src/http-bridge.ts` is the only adapter between Scrypted's `HttpRequest`/`HttpResponse` and Web-standard `Request`/`Response`. Streamed responses (Content-Type: `text/event-stream`) flow through `HttpResponse.sendStream(AsyncGenerator<Buffer>)`; everything else buffers and `send`s.

`src/scrypted.ts` is a thin `getComponent(name)` wrapper around `sdk.systemManager.getComponent(...)` plus re-exports of `systemManager` / `deviceManager` / `mediaManager`. Tools that previously went through `@scrypted/client` now hit the SDK directly.

## OAuth

`src/oauth.ts` is the in-plugin Authorization Server. It implements just enough of OAuth 2.1 + RFC 7591 (Dynamic Client Registration) + RFC 9728 (Protected Resource Metadata) for an MCP client to register itself, redeem a PKCE-protected auth code, and call `/mcp` with a Bearer JWT.

- The signing key is an EC P-256 key pair generated on first boot and persisted in plugin storage as a JWK (`oauth.signing_jwk`). Tokens are ES256 JWTs signed with `src/jwt.ts` (Node's WebCrypto — we deliberately don't pull in `jose` because it's ESM-only and our bundle is CJS).
- DCR registrations live in plugin storage under `oauth.client.<id>`. We accept any registration (PKCE-only public clients), but `ClientStore` caps the total at the `dcr_max_clients` setting (default 100) and evicts the LRU entry on overflow — `last_used_at` is touched on every successful `/authorize` and `/token` grant, with `client_id_issued_at` as the fallback for legacy records.
- Auth codes are in-memory only; they're 60-second one-shots.
- **Refresh tokens are issued on every `/token` response** (both the `authorization_code` and `refresh_token` grants). Default 30-day TTL (configurable via `refresh_token_ttl_sec`), persisted in plugin storage under `oauth.rt.<token>`, single-use rotation: `RefreshTokenStore.consume()` deletes the record before returning it, and the caller issues a fresh one. Replay → `invalid_grant`, client falls back to PKCE, breach is surfaced. We don't track replacement chains, so we can't proactively revoke a chain on detection — use the "Revoke all tokens" Settings button to hard-revoke (drops every RT, every DCR client, rotates the signing key, closes every active session). Admin status is *not* re-checked on refresh; the chain inherits the `/authorize`-time admin check until TTL.
- **Expired refresh tokens are swept every 30 min** by `OAuthService` via `RefreshTokenStore.sweepExpired()` — without this, RTs issued for clients that never come back to refresh would sit until their full TTL elapsed.
- **Everything lives under `/public/`** — `/authorize`, `/token`, `/register`, `/.well-known/*`, `/mcp`, and the issuer URL itself. The MCP TS SDK derives the AS metadata URL by appending `.well-known/oauth-authorization-server` to the issuer; if the issuer were the bare plugin endpoint, that lookup would land on the authenticated path and Scrypted would 401 it before our handler ran (`plugin-http.ts:89`), and the client would fall back to `${origin}/register` and hit Scrypted's root Express 404. So we keep everything public.
- **OIDC discovery URL is also served**, even though we don't issue id_tokens. `buildDiscoveryUrls` (`@modelcontextprotocol/sdk/dist/cjs/client/auth.js:575`) tries three URLs when discovering AS metadata: two at the host root (which we can't serve from a plugin endpoint) and one at `${pathname}/.well-known/openid-configuration` (which we can). We respond at that path with the OAuth doc plus the bare-minimum OIDC fields the schema requires (`subject_types_supported`, `id_token_signing_alg_values_supported`).
- **GET `/mcp` returns 405 (not 401) when no Bearer is present.** The SDK's GET-401 path (`client/streamableHttp.js:100`) doesn't extract the `WWW-Authenticate` `resource_metadata` URL — it just calls `auth()` blindly, which then can't find our metadata. The POST-401 path (`streamableHttp.js:323`) does extract it, so we route the auth bootstrap through there. Returning 405 on GET costs us the optional standalone OOB notification stream (which we don't use).
- **Origin auto-detection.** `originFromRequest` in `oauth.ts` resolves host and protocol independently: host = `x-forwarded-host` → `Host`; proto = `x-forwarded-proto` → port heuristic against `SCRYPTED_INSECURE_PORT` (default 11080, match → http; anything else → https). Independent axes matter because many proxies set proto but leave `Host` alone. Getting this wrong is fatal — every metadata fetch fails and the SDK falls back to `${origin}/register` at the host root.
- **Body parsing.** Scrypted runs `bodyParser.urlencoded` / `json` / `raw` globally and JSON-stringifies the parsed object before handing it to the plugin (`plugin-http.ts:104`). So our `parseBody` helper tries JSON first regardless of original Content-Type, with a fallback to URL-encoded for raw bodies that bypassed the normalizer.
- `/authorize` reads `request.username` regardless: Scrypted's auth middleware populates it from the session cookie even on public endpoints — it just doesn't *enforce* the cookie there (`plugin-http.ts:89` only 401s non-public). A logged-in browser auto-approves; an unauthenticated browser gets our "log in first" hint page instead of Scrypted's plain-text 401.
- `/authorize` is **admin-only**. Scrypted populates `req.aclId` for ACL-restricted users (`aclId` is `undefined` for env-admin / passwd-admin sessions). We reject any request with `aclId` set with a 403 — the MCP tool surface includes admin-grade mutations (`restore_backup`, `set_dotenv`, `restart_server`, …), so we lock the AS to admins. No consent screen otherwise — auto-approve is option (a) from the design discussion.
- **`resource` parameter (RFC 8707) is strictly matched.** Our `aud` is always `ep.resource` (the canonical `/mcp` URL). If a client sends `?resource=` with anything else, `/authorize` rejects with `invalid_target` rather than silently swap — diverging the auth code's bound resource from the issued JWT's `aud` would be invisible to the client.

The MCP `/mcp` path requires the Bearer JWT in `Authorization`, not the Scrypted cookie. On a missing/invalid token we return 401 with `WWW-Authenticate: Bearer resource_metadata="..."` so spec-compliant clients can rediscover the AS.

## Settings

`ScryptedMcpPlugin` implements `Settings`. The Settings tab is the only configuration surface — there is no env-var or file-based config. All values persist in plugin storage under `settings.*` keys and are read on every relevant request, so changes take effect immediately. Group → field mapping (see `getSettings()` in `src/main.ts`):

- **Endpoint** (read-only): `mcp_endpoint_https`, `mcp_endpoint_http` — derived from `endpointManager.getLocalEndpoint`.
- **Configuration** (editable): `dcr_max_clients`, `access_token_ttl_sec`, `refresh_token_ttl_sec`, `max_restore_mb`. Bounds are enforced by `readIntegerSetting()` on read AND by `writeIntegerSetting()` on save, so a hand-edited storage value out of range silently falls back to the default.
- **Status** (read-only + one button): `active_sessions`, `registered_clients`, `active_refresh_tokens`, plus the destructive `revoke_all` button. Counts come from `OAuthService.getStats()` via the same DOM Storage iteration used by the LRU/sweep code.

Token-lifetime constants and bounds (`DEFAULT_ACCESS_TOKEN_TTL_SEC`, `ACCESS_TOKEN_TTL_MIN_SEC`, etc.) live in `oauth.ts` so the AS layer and the Settings layer can't drift on what counts as a valid TTL.

## Module pattern

Each Scrypted runtime component (`logger`, `plugins`, `users`, `alerts`, `addresses`, `cors`, `backup`, `cluster-fork`, `service-control`, `info`, `env-control`) gets one file in `src/tools/`. Every file exports paired `<name>Input` (Zod schema) + `<name>` handler. New tools are wired in `src/main.ts#createMcpServer` via `server.registerTool(name, { description, inputSchema, annotations? }, wrap(handler))`.

`wrap()` catches thrown errors and surfaces them as structured MCP error responses (`isError: true`). It also JSON-stringifies the return value into a single text content block. Tools that need multi-block content (currently just `create_backup` with its base64 ZIP blob) opt out with `wrap(handler, { rawContent: true })` and return the full MCP `content` array themselves.

There is no auto-retry layer. The stdio version had one (`isTransientConnectionError`) because the engine.io socket between the MCP server and Scrypted could drop; in-process there's no socket to drop.

## Destructive tool gating

`restore_backup` is the reference pattern (`src/tools/backup.ts`):

1. Required `confirm` argument equals a tripwire phrase verbatim.
2. MCP elicitation — handler refuses to run if the client doesn't advertise the capability. Better to fail loud than restore silently.
3. `annotations: { destructiveHint: true, idempotentHint: false, ... }`.

Use this same three-gate shape for any new destructive tool that mutates server state irreversibly.

## Backup data flow

Backups travel over the wire as base64 inside MCP `EmbeddedResource` content blocks; nothing touches the Scrypted host filesystem. `create_backup` returns `{ bytes, sha256 }` as a JSON summary plus the inline ZIP blob under a synthetic `scrypted:backup/<timestamp>.zip` URI — the agent saves it wherever it wants on its own box. `restore_backup` takes a base64 string in, decodes to a `Buffer` in memory, computes sha256 (surfaced in the elicitation prompt and in the no-elicitation refusal so the user can verify they're restoring the bytes they think they are), then hands the buffer directly to the `backup` component. Earlier versions staged the ZIP to `os.tmpdir()` for both flows; that was vestigial — the bytes are always in memory anyway, and tmp staging just accumulated multi-MB files across failed/cancelled restores.

## Conventions

- 4-space indent, single quotes, prettier-enforced (`.prettierrc.json`).
- Eslint config (`eslint.config.mjs`) intentionally allows `any` and empty catch (used in best-effort teardowns and untyped Scrypted RPC payloads). `_`-prefixed vars are ignored as unused.
- CommonJS source. No `"type": "module"`. Relative imports do **not** carry `.js` extensions — webpack + ts-loader resolve `./tools/foo` to `./tools/foo.ts` at build time.
- The MCP SDK's auth types are ESM-only and trip TS1541 when imported as types from CJS — we duplicate `AuthInfo` locally in `oauth.ts` rather than fight it. The runtime `require()` resolution works fine because the SDK is dual-published.
- Sibling project `../scrypted-kasa-plugin` is the source of the eslint/prettier/CI/publish patterns. Mirror changes there if relevant.

## Workflow

- Modifying a Scrypted plugin in development (the *target* one, not this MCP plugin): call `reload_plugin` after pushing code to pick up changes.
- Modifying this MCP plugin itself: `npm run build` then `npm run scrypted-deploy-debug` to push it. The plugin reloads in place; existing OAuth registrations and the signing key persist via plugin storage.
- Versioning: bump `package.json`, `package-lock.json` (via `npm install --package-lock-only`), and the `McpServer` literal in `src/main.ts#createMcpServer` together. The publish workflow (`.github/workflows/publish.yml`) verifies the git tag matches.

## Git

- Use `Assisted-By:` (not `Co-Authored-By:`) for Claude attribution in commits.
- Branch per change; open a PR and address Copilot review comments inline rather than dismissing.
