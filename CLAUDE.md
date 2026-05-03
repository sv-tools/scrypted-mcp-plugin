# scrypted-mcp

MCP server that proxies a running Scrypted server (https://scrypted.app) to AI clients (Claude Desktop, Claude Code) over stdio.

## Commands

```bash
npm run build       # tsc → dist/
npm run dev         # tsx, no build step
npm run fmt         # prettier --write
npm run fmt:check   # CI gate
npm run lint        # eslint
npm run lint:fix
```

CI runs `fmt:check`, `lint`, `build` on every push/PR (`.github/workflows/ci.yml`).

## Module pattern

Each Scrypted runtime component (`logger`, `plugins`, `users`, `alerts`, `addresses`, `cors`, `backup`, `cluster-fork`, `service-control`, `info`, `env-control`) gets one file in `src/tools/`. Every file exports paired `<name>Input` (Zod schema) + `<name>` handler. New tools are wired in `src/index.ts` via `server.registerTool(name, { description, inputSchema, annotations? }, wrap(handler))`.

`src/scrypted.ts` is the single shared connection layer — `getClient()` (lazy, cached) and `getComponent(name)` for `systemManager.getComponent(...)` lookups. Don't open additional clients.

## Auto-retry & invalidation

`wrap()` in `src/index.ts` re-runs the handler **once** on a transient transport error (`isTransientConnectionError` matches engine.io / websocket / ECONN* / ETIMEDOUT / etc.). `client.onClose` invalidates the cache so the next call reconnects fresh. The `onClose` invalidation is **scoped to the specific cached promise** — late events from a stale client must not wipe a freshly reconnected one.

Non-idempotent tools opt out: `wrap(handler, { retry: false })`. Currently only `call_device_method` (the agent picks the method name; we can't know if it's idempotent). Server-lifecycle tools (`restart_server`, `update_server`, `restore_backup`) intentionally swallow the disconnect inside the handler and so never enter the retry path.

## Destructive tool gating

`restore_backup` is the reference pattern (`src/tools/backup.ts`):

1. Required `confirm` argument equals a tripwire phrase verbatim.
2. MCP elicitation — handler refuses to run if the client doesn't advertise the capability. Better to fail loud than restore silently.
3. `annotations: { destructiveHint: true, idempotentHint: false, ... }`.

Use this same three-gate shape for any new destructive tool that mutates server state irreversibly.

## Conventions

- 4-space indent, single quotes, prettier-enforced (`.prettierrc.json`).
- Eslint config (`eslint.config.mjs`) intentionally allows `any` and empty catch (used in best-effort teardowns and untyped Scrypted RPC payloads). `_`-prefixed vars are ignored as unused.
- Imports use `.js` extensions in source — required by the ESM/`module: ES2022` setup.
- Sibling project `../scrypted-kasa-plugin` is the source of the eslint/prettier/CI/publish patterns. Mirror changes there if relevant.

## Workflow

- Modifying a Scrypted plugin in development: call `reload_plugin` after pushing code to pick up changes.
- Modifying this MCP server itself: `npm run build`, then the user has to restart their Claude client to pick up the new `dist/index.js`.
- Versioning: bump `package.json`, `package-lock.json` (via `npm install --package-lock-only`), and the `McpServer` literal in `src/index.ts` together. The publish workflow (`.github/workflows/publish.yml`) verifies the git tag matches.

## Git

- Use `Assisted-By:` (not `Co-Authored-By:`) for Claude attribution in commits.
- Branch per change; open a PR and address Copilot review comments inline rather than dismissing.
