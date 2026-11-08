# scrypted-mcp

Let an AI assistant work with your [Scrypted](https://scrypted.app) server. This plugin adds a
[Model Context Protocol (MCP)](https://modelcontextprotocol.io) endpoint to Scrypted, so assistants such as Claude Code
can read logs and alerts, check plugin and device state, manage plugins, and back up the database,
using your Scrypted account to sign in.

- **Runs inside Scrypted.** It's a plugin, not a separate service: install it and there's nothing else to host.
- **Admin-only access.** Sign in with OAuth as a Scrypted admin, or use an API token on your local network.
- **Destructive actions are labelled.** Tools that change or delete things are marked so your assistant asks before
  using them, and restoring a backup needs explicit confirmation.

## Quick start

### 1. Install the plugin

In the Scrypted UI, go to **Plugins → Install Plugin**, search npm for `scrypted-mcp`, and install it. It appears as
**MCP Server** in your installed plugins.

### 2. Pick how to connect

Open **Plugins → MCP Server → Settings**. The **Endpoint** section shows an HTTP and an HTTPS URL. Which one you use
depends on how your machine reaches Scrypted:

- **On your local network** (most setups): use the HTTP URL with an API token. MCP clients won't run OAuth over plain
  HTTP or against Scrypted's default self-signed certificate.
- **Over HTTPS with a certificate your machine trusts** (a reverse proxy or tunnel): use the HTTPS URL and sign in with
  OAuth.

### 3. Add it to your assistant

**Claude Code, on your local network (API token):** in **Settings → API Tokens**, type a name for the client and save.
The token is shown once, along with a ready-to-paste command like this one:

```bash
claude mcp add --transport http --scope user scrypted http://your-scrypted-host:11080/endpoint/scrypted-mcp/public/mcp \
  --header "Authorization: Bearer smcp_..."
```

**Claude Code, over trusted HTTPS (OAuth):** first open the Scrypted UI in your usual browser and sign in as an admin,
since the MCP sign-in reuses that session. Then add the server:

```bash
claude mcp add --transport http --scope user scrypted https://your-scrypted-host/endpoint/scrypted-mcp/public/mcp
```

The first time Claude Code uses it, a browser window opens and approves the sign-in automatically.

**Claude Desktop and claude.ai:** not supported yet. See [Other clients](#other-clients) below.

### 4. Try it

Ask your assistant something like:

- "Are there any Scrypted alerts?"
- "Which plugins are installed, and are any out of date?"
- "Show me errors in the Scrypted logs from the last hour."
- "Make a backup of my Scrypted database."

## What you can do

| Area                    | For example                                                     | Changes things? |
|-------------------------|-----------------------------------------------------------------|-----------------|
| Plugins                 | List, inspect, install, update, reload, read or change storage  | Some tools      |
| Devices                 | List devices, read their state, call device methods             | Some tools      |
| Logs & alerts           | Read server logs and alerts, clear them                         | Some tools      |
| Server administration   | Version and environment, restart, update, edit `.env`           | Some tools      |
| Users                   | List, add, or remove Scrypted users                             | Some tools      |
| Network                 | Read or set local and external addresses, CORS                  | Some tools      |
| Cluster                 | List cluster workers                                            | No              |
| Backup & restore        | Back up the database; restore from a backup                     | Restore only    |

Tools are annotated as read-only or destructive, so a well-behaved client can let read-only calls through and ask you
about the rest. `call_device_method` can call any method on any device, so it has no annotation, and clients treat it
as potentially destructive. The full list is in the [tool reference](#tool-reference) below.

## Tool reference

### Plugins

- `list_plugins` — All installed plugins with id / pluginId / name / type.
- `get_plugin_info` — pid, pending RPC calls, object count for one plugin.
- `reload_plugin` — Restart a plugin host (picks up code changes).
- `kill_plugin` — Kill a plugin host without auto-reload.
- `install_plugin` — Install / upgrade a plugin from npm.
- `update_plugins` — Upgrade every installed plugin to its latest npm version.
- `npm_info` — Query npmjs.org via the Scrypted server. Use `"scrypted-kasa"` for package metadata, or
  `"-/v1/search?text=keywords:scrypted-plugin"` to discover plugins.
- `rename_device_id` — Rename a Scrypted device id (briefly kills the owning plugin).
- `set_mixins` — Replace the list of mixins on a device. Read `get_device` first if you only want to add/remove one.
- `get_storage` / `set_storage` — Read / replace a plugin device's persistent KV storage.
- `get_id_for_native_id` — Reverse-lookup a Scrypted device id from a plugin's internal `nativeId`.
- `disconnect_clients` — Disconnect all websocket clients of a plugin (forces reconnection).
- `clear_console` — Clear a plugin device's console buffer.

### Devices

- `list_devices` — All devices. Filter by interface / type / name substring.
- `get_device` — Snapshot every state property on a device.
- `call_device_method` — Invoke a method on a device (`turnOn`, `setBrightness`, `getSettings`, …).

### Logs & alerts

- `get_logs` — Retained server logs (~48 h). Filter by component, level, `sinceMs`.
- `clear_logs` — Clear the server-side log buffer.
- `list_alerts` — Persisted alerts (plugin crashes, warnings).
- `remove_alert` — Remove a single alert by id.
- `clear_alerts` — Remove all alerts.

### Server administration

- `get_server_info` — Scrypted version + `SCRYPTED_*` environment variables.
- `restart_server` — Restart the Scrypted server. The MCP connection drops.
- `update_server` — Trigger a server update (webhook or `.update` file + restart).
- `get_dotenv` — Read the contents of the Scrypted `.env` file.
- `set_dotenv` — Overwrite the Scrypted `.env` file (verbatim — include all keys).

### Users

- `list_users` — All Scrypted user accounts (username + admin flag).
- `add_user` — Create a user. Omit `aclId` to create an admin.
- `remove_user` — Delete a user by username.

### Network

- `get_local_addresses` — Configured local addresses / interface names.
- `set_local_addresses` — Replace local addresses. Pass interface names (`en0`) or IPs.
- `get_external_addresses` — External (publicly reachable) addresses for a plugin endpoint.
- `set_external_addresses` — Replace external addresses for a plugin endpoint.
- `get_cors` — CORS origin allowlist for a plugin endpoint.
- `set_cors` — Replace the CORS origin allowlist for a plugin endpoint.

### Cluster

- `list_cluster_workers` — Registered cluster workers (id, name, labels, mode, address, fork count).

### Backup & restore

- `create_backup` — Snapshot the Scrypted database. Returns the ZIP inline as a base64-encoded `EmbeddedResource` (plus
  a JSON summary with byte count + sha256) for the agent to save locally. Nothing is written to the Scrypted host
  filesystem.
- `restore_backup` — Restore from a base64-encoded backup ZIP. The MCP host decodes it in memory and hands the bytes
  directly to Scrypted — no tmp file is staged on the host. **Destructive** — wipes the database and installed plugin
  files.

`restore_backup` is gated three ways before it runs:

1. The `confirm` argument must equal the exact string `RESTORE FROM BACKUP`.
2. The MCP client must support [elicitation](https://modelcontextprotocol.io/specification/server/elicitation) and the
   user must explicitly select `RESTORE` in the confirmation dialog. Without elicitation support the tool refuses to
   run.
3. The tool is annotated `destructiveHint: true` so well-behaved clients require user approval before the call.

The MCP connection drops when the server restarts at the end of a successful restore.

## Other clients

Any MCP client that supports Streamable HTTP and OAuth, and signs in through a loopback redirect
(`http://localhost:<port>/...`, as native clients such as Claude Code do), can connect with the HTTPS endpoint URL.

A client that can send a custom `Authorization` header can also connect with an
[API token](#oauth-needs-https-use-an-api-token-otherwise), without OAuth.

### Claude Desktop and claude.ai

Not supported yet. These apps connect from Anthropic's cloud and sign in with the redirect URI
`https://claude.ai/api/mcp/auth_callback`. The plugin only accepts loopback redirect URIs, because it approves sign-ins
automatically for a logged-in Scrypted admin: a public redirect would let anyone who registers a client collect an
authorization code from an admin's browser. Use Claude Code instead.

## Settings

The plugin's Settings tab in the Scrypted UI surfaces both configurable knobs and a live health snapshot. Open
**Plugins → MCP Server → Settings** to see them.

### Endpoint

Two read-only URLs the plugin computes from the live Scrypted listening address — paste whichever one matches how you're
reaching Scrypted.

- **MCP endpoint URL (HTTPS)** — for OAuth clients, when the certificate is one your machine trusts (e.g. behind a
  reverse proxy).
- **MCP endpoint URL (HTTP)** — for local-network clients and debugging where the self-signed HTTPS cert is awkward.
  Use it with an API token (OAuth won't run over plain HTTP). Don't expose to the internet.

### API Tokens

- **Create API token** — type a client name and save to create a token. The plaintext appears once, in a read-only
  field with a ready-to-paste `claude mcp add` command. It's never stored, and refreshing the page hides it for good. If
  you lose it, create a new token and revoke the old one.
- **API tokens** — the existing tokens with their creation and last-used dates. Remove an entry and save to revoke it.

### Configuration

| Setting                 | Default        | Range           | What it does                                                                                                                                      |
|-------------------------|----------------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `dcr_max_clients`       | 100            | ≥ 1             | Cap on persisted DCR client registrations. When a `/register` would push the total above this, the least-recently-used registration is evicted.   |
| `access_token_ttl_sec`  | 3600 (1 h)     | 60 – 86400      | Lifetime of issued JWT access tokens. Shorter = tighter security; longer = less re-auth churn.                                                    |
| `refresh_token_ttl_sec` | 2592000 (30 d) | 3600 – 31536000 | Lifetime of issued refresh tokens. Each refresh rotates the token (single-use), so this is the upper bound on how long a stolen RT remains valid. |
| `max_restore_mb`        | 500            | 1 – 10240       | Maximum decoded backup size that `restore_backup` will accept. Bump if your Scrypted database exceeds the default.                                |

All four values are read at request time, so changes take effect on the next inbound request — no plugin reload
required.

### Status

Read-only health fields, refreshed each time the Settings tab is opened.

- **Active MCP sessions** — In-memory sessions currently held open. Idle sessions are reaped after 1 h.
- **Registered DCR clients** — Persisted client registrations in plugin storage.
- **Persisted refresh tokens** — Refresh tokens currently in plugin storage.
- **Revoke all tokens & disconnect clients** — DESTRUCTIVE button. Drops every refresh token, deletes every DCR
  registration, revokes every API token, rotates the JWT signing key (existing access tokens immediately stop verifying), and closes all active
  MCP sessions. Every client will need to re-register and re-authenticate. Use it if you suspect a token leak or want to
  force a clean slate.

## How it works

### Endpoint

The endpoint (`<your-scrypted-base-url>/endpoint/scrypted-mcp/public/mcp`) speaks
[Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http).
Use whichever base you use for the Scrypted UI — `https://host:10443` if you're on the secure port, or
`http://host:11080` if you're on the insecure one. The plugin auto-detects the protocol from the inbound port (or trusts
`x-forwarded-proto` if you have a reverse proxy in front), so OAuth metadata documents come back with URLs your client
can actually reach.

You don't need to point clients at any other URL — the protected-resource metadata at
`/endpoint/scrypted-mcp/public/.well-known/oauth-protected-resource` advertises the authorization server, which
advertises `/authorize`, `/token`, `/register`, and the JWKS document.

### Authentication

The plugin is its own OAuth 2.1 Authorization Server. It supports:

- **Dynamic Client Registration** (RFC 7591) — your MCP client registers itself the first time it connects; no manual
  config needed.
- **Authorization Code + PKCE** (S256) — the only supported flow. Public clients only, no `client_secret`.
- **ES256 JWT access tokens**, valid 1 hour by default, signed with an EC P-256 key generated on the plugin's first boot and
  persisted in plugin storage.
- **Rotating refresh tokens**, valid 30 days by default. Every `/token` response includes a fresh `refresh_token`; redeeming one
  invalidates the previous, so a stolen RT works at most once before the legitimate client's next refresh fails and
  forces re-auth (surfacing the breach). Refresh tokens persist in plugin storage; *Revoke all tokens* in Settings hard-revokes every chain.

The login step is just **your existing Scrypted session**. When the MCP client opens `/authorize` in your browser,
Scrypted's auth pipeline checks the cookie and populates the username for us. Auto-approve happens immediately — no
consent screen. Only Scrypted admin users are authorized.

### OAuth needs HTTPS: use an API token otherwise

MCP clients only run the OAuth token exchange over HTTPS with a trusted certificate, or over plain HTTP to `localhost`.
Claude Code, for example, fails with `OAuth token requests MUST use TLS (localhost / 127.0.0.1 / ::1 are exempt)`. That
rules out OAuth for the usual LAN setups: `http://<ip>:11080`, or `https://<ip>:10443` with Scrypted's self-signed
certificate.

For those, create a static **API token** in the plugin's Settings (*API Tokens → Create API token*: type a name and
save). The token is shown only once; copy it right away and send it as a Bearer header. The server never answers with a 401, so the
client never starts OAuth:

```bash
claude mcp add --transport http --scope user scrypted http://your-scrypted-host:11080/endpoint/scrypted-mcp/public/mcp \
  --header "Authorization: Bearer smcp_..."
```

API tokens don't expire. Only their SHA-256 is stored. Revoke one by removing it from the *API tokens* list in
Settings, or use *Revoke all tokens*. A token grants the same admin-level access as an OAuth session, and over plain
HTTP it travels in cleartext, so keep the HTTP port off the internet.

## Troubleshooting

### The sign-in page says to log into Scrypted first

The plugin signs you in with your existing Scrypted session, so it needs one in the same browser. Open the Scrypted UI
in that browser, sign in as an admin, then retry the connection from your MCP client.

### `HTTP 404 ... Cannot POST /register`

If your MCP client logs `HTTP 404 ... Cannot POST /register` (or any other path at the host root), the plugin's OAuth
metadata advertised URLs your client couldn't reach. Most often this means the protocol got mis-detected — check that
your client's URL matches the port (https → 10443, http → 11080) and that nothing in front of Scrypted is rewriting
`Host` without forwarding `x-forwarded-proto`.

After fixing the URL, re-run `claude mcp remove scrypted` and re-add it (or equivalent for your client) to clear any
cached OAuth discovery state.

### Claude Code: re-auth after a connection loss

If the connection drops and you clear the stored credentials in Claude Code (`/mcp` → Scrypted → *Clear authentication*),
**click *Reconnect* before *Authenticate***. Otherwise the auth flow fails with a discovery 404.

Why: the MCP SDK only learns where this plugin's Authorization Server lives by reading the
`WWW-Authenticate: Bearer resource_metadata="..."` header that `/mcp` returns on a 401. *Reconnect* triggers a fresh POST
that produces that 401 and caches the metadata URL; *Authenticate* alone uses whatever discovery state was already
cached, and after a *Clear authentication* there is none — so it falls back to default URLs at the host root, which
Scrypted's root Express returns 404 for. Reconnect first → metadata cached → Authenticate succeeds.

## Develop

```bash
npm install
npm run build           # → out/main.nodejs.js + out/plugin.zip
npm run scrypted-deploy # push to a running Scrypted server
```

See the [Scrypted SDK docs](https://github.com/koush/scrypted/tree/main/sdk) for plugin development specifics.
