# scrypted-mcp

A [Scrypted](https://scrypted.app) plugin that exposes a [Streamable HTTP Model Context Protocol](https://modelcontextprotocol.io/specification/basic/transports#streamable-http) endpoint, with OAuth backed by Scrypted user accounts. AI assistants (Claude Desktop, Claude Code, etc.) connect to your running Scrypted server and call MCP tools to inspect logs, manage plugins, query devices, and snapshot the database.

## Endpoint

Once installed and the plugin is running, the MCP endpoint is:

```
<your-scrypted-base-url>/endpoint/scrypted-mcp/public/mcp
```

Use whichever base you use for the Scrypted UI — `https://host:10443` if you're on the secure port, or `http://host:11080` if you're on the insecure one. The plugin auto-detects the protocol from the inbound port (or trusts `x-forwarded-proto` if you have a reverse proxy in front), so OAuth metadata documents come back with URLs your client can actually reach.

You don't need to point clients at any other URL — the protected-resource metadata at `/endpoint/scrypted-mcp/public/.well-known/oauth-protected-resource` advertises the authorization server, which advertises `/authorize`, `/token`, `/register`, and the JWKS document.

## Authentication

The plugin is its own OAuth 2.1 Authorization Server. It supports:

- **Dynamic Client Registration** (RFC 7591) — your MCP client registers itself the first time it connects; no manual config needed.
- **Authorization Code + PKCE** (S256) — the only supported flow. Public clients only, no `client_secret`.
- **ES256 JWT access tokens**, valid 1 hour, signed with an EC P-256 key generated on the plugin's first boot and persisted in plugin storage.

The login step is just **your existing Scrypted session**. When the MCP client opens `/authorize` in your browser, Scrypted's auth pipeline checks the cookie and populates the username for us. Auto-approve happens immediately — no consent screen.

**First-time UX:** if you aren't already logged into the Scrypted UI in the same browser, hitting `/authorize` shows a "log into Scrypted first" hint page. Sign in to Scrypted in another tab, then retry the connection from your MCP client.

## Tools

### Plugins

- `list_plugins` — All installed plugins with id / pluginId / name / type.
- `get_plugin_info` — pid, pending RPC calls, object count for one plugin.
- `reload_plugin` — Restart a plugin host (picks up code changes).
- `kill_plugin` — Kill a plugin host without auto-reload.
- `install_plugin` — Install / upgrade a plugin from npm.
- `update_plugins` — Upgrade every installed plugin to its latest npm version.
- `npm_info` — Query npmjs.org via the Scrypted server. Use `"scrypted-kasa"` for package metadata, or `"-/v1/search?text=keywords:scrypted-plugin"` to discover plugins.
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

- `create_backup` — Snapshot the Scrypted database. Writes a staged ZIP to `os.tmpdir()` on the Scrypted host (auto-cleaned after 1 h) and returns the bytes inline as a base64-encoded `EmbeddedResource` for the agent to save locally.
- `restore_backup` — Restore from a base64-encoded backup ZIP. **Destructive** — wipes the database and installed plugin files.

`restore_backup` is gated three ways before it runs:

1. The `confirm` argument must equal the exact string `RESTORE FROM BACKUP`.
2. The MCP client must support [elicitation](https://modelcontextprotocol.io/specification/server/elicitation) and the user must explicitly select `RESTORE` in the confirmation dialog. Without elicitation support the tool refuses to run.
3. The tool is annotated `destructiveHint: true` so well-behaved clients require user approval before the call.

The MCP connection drops when the server restarts at the end of a successful restore.

## Install

Search for `scrypted-mcp` in your Scrypted plugin browser, or install via the npm registry:

```bash
# from the Scrypted UI: Plugins → Install Plugin → Search npm: scrypted-mcp
```

The plugin appears as **MCP Server** under your installed plugins. Click into it to see the endpoint URL in the console output on first boot.

## Connect

### Claude Desktop

In `Settings → Developer → Edit Config` add (replace the URL with whichever base your Scrypted UI uses — `https://host:10443` or `http://host:11080`):

```json
{
  "mcpServers": {
    "scrypted": {
      "type": "streamable-http",
      "url": "https://your-scrypted-host/endpoint/scrypted-mcp/public/mcp"
    }
  }
}
```

Open the Scrypted UI and sign in (in the same browser Claude Desktop will use for OAuth). Then start a Claude Desktop session — it will redirect you through `/authorize`, register itself, and connect.

### Claude Code

```bash
claude mcp add scrypted --scope=user --transport http https://your-scrypted-host/endpoint/scrypted-mcp/public/mcp
```

The first call triggers the OAuth flow in your browser.

## Troubleshooting

If your MCP client logs `HTTP 404 ... Cannot POST /register` (or any other path at the host root), the plugin's OAuth metadata advertised URLs your client couldn't reach. Most often this means the protocol got mis-detected — check that your client's URL matches the port (https → 10443, http → 11080) and that nothing in front of Scrypted is rewriting `Host` without forwarding `x-forwarded-proto`.

After fixing the URL, re-run `claude mcp remove scrypted` and re-add it (or equivalent for your client) to clear any cached OAuth discovery state.

## Develop

```bash
npm install
npm run build           # → out/main.nodejs.js + out/plugin.zip
npm run scrypted-deploy # push to a running Scrypted server
```

See the [Scrypted SDK docs](https://github.com/koush/scrypted/tree/main/sdk) for plugin development specifics.
