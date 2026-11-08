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

The plugin is one process inside Scrypted. `src/main.ts` declares `ScryptedMcpPlugin extends ScryptedDeviceBase implements HttpRequestHandler` and registers the full MCP tool surface in `createMcpServer`. The plugin speaks MCP **2026-07-28** through `@modelcontextprotocol/server` v2 and is **stateless**: there is no session map, no `Mcp-Session-Id`, and nothing about a client is held between requests. Inbound HTTP requests are dispatched in `onRequest`:

1. `OAuthService.handle()` claims `/authorize`, `/token`, `/register`, and the four `.well-known/*` documents (`oauth-protected-resource`, `oauth-authorization-server`, `openid-configuration`, `jwks.json`). If it returns true, the response is already populated.
2. Otherwise, if the path resolves to `/mcp`, we verify the Bearer JWT, bridge the Scrypted request to a Web-standard `Request`, and route it by protocol era (`isLegacyRequest`):
   - **2026-07-28** requests go to the `createMcpHandler` handler (`legacy: 'reject'`). Each request carries its own protocol version and client capabilities in `_meta`; clients start with `server/discover`, and the handler may stream a response as SSE.
   - **2025-era** requests (`initialize` + session) go to `serveLegacy()`: a throwaway `McpServer` and `WebStandardStreamableHTTPServerTransport` per request, with `sessionIdGenerator: undefined` and `enableJsonResponse: true`, closed in `finally`. Legacy clients always get plain JSON, never SSE, and non-POST gets 405.
3. Anything else returns 404.

`src/http-bridge.ts` is the only adapter between Scrypted's `HttpRequest`/`HttpResponse` and Web-standard `Request`/`Response`. Streamed responses (Content-Type: `text/event-stream`) flow through `HttpResponse.sendStream(AsyncGenerator<Buffer>)`; everything else buffers and `send`s.

**Keep legacy on JSON.** On Scrypted ≤ 0.147.0, every `sendStream()` leaks one loopback cluster connection (#89, fixed upstream in koush/scrypted@ea52522, unreleased). Answering 2025-era clients with SSE leaked about one connection per call; JSON leaks none. The 2026-07-28 path only uses SSE for `subscriptions/listen`, and since we advertise `tools.listChanged: false` it's acknowledged with nothing subscribed and closes immediately; don't flip that capability without a streaming story for #89.

Two SSE behaviours are inherited from the SDK (`@modelcontextprotocol/server`) rather than implemented here, and both depend on the bridge staying byte- and header-transparent:

- **Keep-alive.** The transport writes `: keepalive` comment frames into the SSE stream every 15s (`keepAliveMs`, default `DEFAULT_SSE_KEEP_ALIVE_MS`). This is what stops a reverse proxy from reaping a stream that idles — the `subscriptions/listen` stream, or a long tool call such as `create_backup` on a large database. (The `restore_backup` confirmation no longer holds a stream open while the human answers; see Destructive tool gating.) `readableStreamToBufferGenerator` must therefore keep forwarding every non-empty chunk; the only chunks it may drop are zero-length ones.
- **Proxy hints.** The transport sets `X-Accel-Buffering: no` and `Cache-Control: no-cache, no-transform` on SSE responses. These reach the client only because `fromWebResponse` copies the full header set through `headersToPlain` — don't switch it to an allowlist of known headers.

Request `Content-Type` is validated by parsed media type, not substring match, so `application/json` and `application/json; charset=utf-8` both pass but a comma-joined duplicate header 415s.

`src/scrypted.ts` is a thin `getComponent(name)` wrapper around `sdk.systemManager.getComponent(...)` plus re-exports of `systemManager` / `deviceManager` / `mediaManager`. Tools that previously went through `@scrypted/client` now hit the SDK directly.

## OAuth

`src/oauth.ts` is the in-plugin Authorization Server. It implements just enough of OAuth 2.1 + RFC 7591 (Dynamic Client Registration) + RFC 9728 (Protected Resource Metadata) for an MCP client to register itself, redeem a PKCE-protected auth code, and call `/mcp` with a Bearer JWT.

- The signing key is an EC P-256 key pair generated on first boot and persisted in plugin storage as a JWK (`oauth.signing_jwk`). Tokens are ES256 JWTs signed with `src/jwt.ts` (Node's WebCrypto — we deliberately don't pull in `jose` because it's ESM-only and our bundle is CJS).
- DCR registrations live in plugin storage under `oauth.client.<id>`. We accept any registration (PKCE-only public clients), but `ClientStore` caps the total at the `dcr_max_clients` setting (default 100) and evicts the LRU entry on overflow — `last_used_at` is touched on every successful `/authorize` and `/token` grant, with `client_id_issued_at` as the fallback for legacy records.
- Auth codes are in-memory only; they're 60-second one-shots.
- **Refresh tokens are issued on every `/token` response** (both the `authorization_code` and `refresh_token` grants). Default 30-day TTL (configurable via `refresh_token_ttl_sec`), persisted in plugin storage under `oauth.rt.<token>`, single-use rotation: `RefreshTokenStore.consume()` deletes the record before returning it, and the caller issues a fresh one. Replay → `invalid_grant`, client falls back to PKCE, breach is surfaced. We don't track replacement chains, so we can't proactively revoke a chain on detection — use the "Revoke all tokens" Settings button to hard-revoke (drops every RT, every DCR client, rotates the signing key and the request-state key, which voids any pending `restore_backup` confirmation). Admin status is *not* re-checked on refresh; the chain inherits the `/authorize`-time admin check until TTL.
- **Expired refresh tokens are swept every 30 min** by `OAuthService` via `RefreshTokenStore.sweepExpired()` — without this, RTs issued for clients that never come back to refresh would sit until their full TTL elapsed.
- **Everything lives under `/public/`** — `/authorize`, `/token`, `/register`, `/.well-known/*`, `/mcp`, and the issuer URL itself. The MCP TS SDK derives the AS metadata URL by appending `.well-known/oauth-authorization-server` to the issuer; if the issuer were the bare plugin endpoint, that lookup would land on the authenticated path and Scrypted would 401 it before our handler ran (`plugin-http.ts:89`), and the client would fall back to `${origin}/register` and hit Scrypted's root Express 404. So we keep everything public.
- **OIDC discovery URL is also served**, even though we don't issue id_tokens. `buildDiscoveryUrls` (`@modelcontextprotocol/sdk/dist/cjs/client/auth.js:575`) tries three URLs when discovering AS metadata: two at the host root (which we can't serve from a plugin endpoint) and one at `${pathname}/.well-known/openid-configuration` (which we can). We respond at that path with the OAuth doc plus the bare-minimum OIDC fields the schema requires (`subject_types_supported`, `id_token_signing_alg_values_supported`).
- **GET `/mcp` returns 405 (not 401) when no Bearer is present.** The SDK's GET-401 path (`client/streamableHttp.js:100`) doesn't extract the `WWW-Authenticate` `resource_metadata` URL — it just calls `auth()` blindly, which then can't find our metadata. The POST-401 path (`streamableHttp.js:323`) does extract it, so we route the auth bootstrap through there. Returning 405 on GET costs nothing: 2026-07-28 has no GET stream (notifications come over `subscriptions/listen`), and the legacy path is JSON-only.
- **Origin auto-detection.** `originFromRequest` in `oauth.ts` resolves host and protocol independently: host = `x-forwarded-host` → `Host`; proto = `x-forwarded-proto` → port heuristic against `SCRYPTED_INSECURE_PORT` (default 11080, match → http; anything else → https). Independent axes matter because many proxies set proto but leave `Host` alone. Getting this wrong is fatal — every metadata fetch fails and the SDK falls back to `${origin}/register` at the host root.
- **Body parsing.** Scrypted runs `bodyParser.urlencoded` / `json` / `raw` globally and JSON-stringifies the parsed object before handing it to the plugin (`plugin-http.ts:104`). So our `parseBody` helper tries JSON first regardless of original Content-Type, with a fallback to URL-encoded for raw bodies that bypassed the normalizer.
- `/authorize` reads `request.username` regardless: Scrypted's auth middleware populates it from the session cookie even on public endpoints — it just doesn't *enforce* the cookie there (`plugin-http.ts:89` only 401s non-public). A logged-in browser auto-approves; an unauthenticated browser gets our "log in first" hint page instead of Scrypted's plain-text 401.
- `/authorize` is **admin-only**. Scrypted populates `req.aclId` for ACL-restricted users (`aclId` is `undefined` for env-admin / passwd-admin sessions). We reject any request with `aclId` set with a 403 — the MCP tool surface includes admin-grade mutations (`restore_backup`, `set_dotenv`, `restart_server`, …), so we lock the AS to admins. No consent screen otherwise — auto-approve is option (a) from the design discussion.
- **`resource` parameter (RFC 8707) is strictly matched.** Our `aud` is always `ep.resource` (the canonical `/mcp` URL). If a client sends `?resource=` with anything else, `/authorize` rejects with `invalid_target` rather than silently swap — diverging the auth code's bound resource from the issued JWT's `aud` would be invisible to the client.
- **Static API tokens** (`src/api-tokens.ts`) are the non-OAuth path. MCP clients refuse the OAuth token exchange over plain HTTP to non-loopback hosts (and self-signed HTTPS fails cert checks), so LAN users send `Authorization: Bearer smcp_...` instead and never see a 401. Tokens are `smcp_` + 32 random bytes; only the SHA-256 is persisted, under `apitoken.<sha256hex>`, so verification is one `getItem`. The `smcp_` prefix can't start a JWT (`eyJ...`), so `verifyBearer` branches on it. Created/revoked from Settings (*API Tokens* group); the plaintext is never persisted: it's held in memory and returned by exactly one `getSettings()` call (then cleared), with a 5 min cap if Settings is never reopened. Lost tokens are regenerated, not recovered. `revokeAll` drops them too.

The MCP `/mcp` path requires a Bearer JWT or API token in `Authorization`, not the Scrypted cookie. On a missing/invalid token we return 401 with `WWW-Authenticate: Bearer resource_metadata="..."` so spec-compliant clients can rediscover the AS.

## Settings

`ScryptedMcpPlugin` implements `Settings`. The Settings tab is the only configuration surface — there is no env-var or file-based config. All values persist in plugin storage under `settings.*` keys and are read on every relevant request, so changes take effect immediately. Group → field mapping (see `getSettings()` in `src/main.ts`):

- **Endpoint** (read-only): `mcp_endpoint_https`, `mcp_endpoint_http` — derived from `endpointManager.getLocalEndpoint`.
- **API Tokens**: `api_token_create` (string; saving a non-empty name creates a token), `api_token_new` (read-only, one-shot in-memory plaintext of the last-created token), one `api_token_revoke.<id>` button per token (click revokes it; `api_tokens` is the read-only "none" row when there are no tokens, and a no-op key otherwise).
- **Configuration** (editable): `dcr_max_clients`, `access_token_ttl_sec`, `refresh_token_ttl_sec`, `max_restore_mb`. Bounds are enforced by `readIntegerSetting()` on read AND by `writeIntegerSetting()` on save, so a hand-edited storage value out of range silently falls back to the default.
- **Status** (read-only + one button): `registered_clients`, `active_refresh_tokens`, plus the destructive `revoke_all` button. (There is no `active_sessions` count; the server is stateless.) Counts come from `OAuthService.getStats()` via the same DOM Storage iteration used by the LRU/sweep code.

Token-lifetime constants and bounds (`DEFAULT_ACCESS_TOKEN_TTL_SEC`, `ACCESS_TOKEN_TTL_MIN_SEC`, etc.) live in `oauth.ts` so the AS layer and the Settings layer can't drift on what counts as a valid TTL.

## Module pattern

Each Scrypted runtime component (`logger`, `plugins`, `users`, `alerts`, `addresses`, `cors`, `backup`, `cluster-fork`, `service-control`, `info`, `env-control`) gets one file in `src/tools/`. Every file exports paired `<name>Input` (Zod schema) + `<name>` handler. New tools are wired in `src/main.ts#createMcpServer` via `server.registerTool(name, { description, inputSchema, annotations? }, wrap(handler))`.

`wrap()` catches thrown errors and surfaces them as structured MCP error responses (`isError: true`). It also JSON-stringifies the return value into a single text content block. Tools that need multi-block content (currently just `create_backup` with its base64 ZIP blob) opt out with `wrap(handler, { rawContent: true })` and return the full MCP `content` array themselves.

There is no auto-retry layer. The stdio version had one (`isTransientConnectionError`) because the engine.io socket between the MCP server and Scrypted could drop; in-process there's no socket to drop.

## Destructive tool gating

`restore_backup` is the reference pattern (`src/tools/backup.ts`):

1. Required `confirm` argument equals a tripwire phrase verbatim.
2. A human confirmation through elicitation. On 2026-07-28 this is a multi-round-trip request: the first call returns `inputRequired` with a form, plus a sealed `requestState` (an HMAC from `createRequestStateCodec`, keyed by `mcp.request_state_key` in plugin storage). The state is bound to the method and the OAuth client, expires after 300s, and records the payload's sha256. The client retries with `inputResponses` + `requestState`; the handler checks that the sha256 still matches before acting. An `inputResponses` without valid state just gets the prompt again, and tampered state is rejected by the SDK (`requestState.verify`). `legacyShim: false`, so 2025-era clients can't confirm and the tool refuses for them. Better to fail loud than restore silently.
3. `annotations: { destructiveHint: true, idempotentHint: false, ... }`.

State that must survive between rounds goes in `requestState`, never in memory: requests can land on a freshly reloaded plugin.

Use this same three-gate shape for any new destructive tool that mutates server state irreversibly.

## Backup data flow

Backups travel over the wire as base64 inside MCP `EmbeddedResource` content blocks; nothing touches the Scrypted host filesystem. `create_backup` returns `{ bytes, sha256 }` as a JSON summary plus the inline ZIP blob under a synthetic `scrypted:backup/<timestamp>.zip` URI — the agent saves it wherever it wants on its own box. `restore_backup` takes a base64 string in, decodes to a `Buffer` in memory, computes sha256 (surfaced in the elicitation prompt and in the no-elicitation refusal so the user can verify they're restoring the bytes they think they are), then hands the buffer directly to the `backup` component. Earlier versions staged the ZIP to `os.tmpdir()` for both flows; that was vestigial — the bytes are always in memory anyway, and tmp staging just accumulated multi-MB files across failed/cancelled restores.

## Conventions

- 4-space indent, single quotes, prettier-enforced (`.prettierrc.json`).
- Eslint config (`eslint.config.mjs`) intentionally allows `any` and empty catch (used in best-effort teardowns and untyped Scrypted RPC payloads). `_`-prefixed vars are ignored as unused.
- CommonJS source. No `"type": "module"`. Relative imports do **not** carry `.js` extensions — webpack + ts-loader resolve `./tools/foo` to `./tools/foo.ts` at build time.
- `oauth.ts` keeps a local mirror of the SDK's `AuthInfo` so the OAuth layer doesn't depend on the SDK; `main.ts` imports the SDK type as `SdkAuthInfo` where it hands auth to the handler. The SDK is dual-published, so CJS `require()` works.
- Sibling project `../scrypted-kasa-plugin` is the source of the eslint/prettier/CI/publish patterns. Mirror changes there if relevant.

## Workflow

- Modifying a Scrypted plugin in development (the *target* one, not this MCP plugin): call `reload_plugin` after pushing code to pick up changes.
- Modifying this MCP plugin itself: `npm run build` then `npm run scrypted-deploy-debug` to push it. The plugin reloads in place; existing OAuth registrations and the signing key persist via plugin storage.
- Versioning: bump `package.json`, `package-lock.json` (via `npm install --package-lock-only`), and the `McpServer` literal in `src/main.ts#createMcpServer` together. The publish workflow (`.github/workflows/publish.yml`) verifies the git tag matches.
- **Published tarball must contain `dist/plugin.zip`** — Scrypted's `installNpm` (`server/src/runtime.ts:608`) reads `files['package/dist/plugin.zip']` and calls `.toString('base64')` on it; if the file is missing, the install fails with `Cannot read properties of undefined (reading 'toString')`. We rely on the `"files": ["dist/plugin.zip"]` whitelist in `package.json` to ensure it lands in the tarball — without that, npm falls back to `.gitignore`, which excludes `dist/` and breaks the install. v1.0.0 / v1.0.1 hit exactly this trap; v1.0.2 added the whitelist.

## Git

- Use `Assisted-By:` (not `Co-Authored-By:`) for Claude attribution in commits.
- Branch per change; open a PR and address Copilot review comments inline rather than dismissing.
