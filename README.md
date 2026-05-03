# scrypted-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Scrypted](https://scrypted.app). Lets AI assistants (Claude Desktop, Claude Code, etc.) inspect logs, manage plugins, and query devices on a running Scrypted server.

## Tools

### Plugins

| Tool | Purpose |
|---|---|
| `list_plugins` | All installed plugins with id / pluginId / name / type. |
| `get_plugin_info` | pid, pending RPC calls, object count for one plugin. |
| `reload_plugin` | Restart a plugin host (picks up code changes). |
| `kill_plugin` | Kill a plugin host without auto-reload. |
| `install_plugin` | Install / upgrade a plugin from npm. |
| `update_plugins` | Upgrade every installed plugin to its latest npm version. |
| `npm_info` | Query npmjs.org via the Scrypted server. Use `"scrypted-kasa"` for package metadata, or `"-/v1/search?text=keywords:scrypted-plugin"` to discover plugins. |
| `rename_device_id` | Rename a Scrypted device id (briefly kills the owning plugin). |
| `set_mixins` | Replace the list of mixins on a device. Read `get_device` first if you only want to add/remove one. |
| `get_storage` / `set_storage` | Read / replace a plugin device's persistent KV storage. |
| `get_id_for_native_id` | Reverse-lookup a Scrypted device id from a plugin's internal `nativeId`. |
| `disconnect_clients` | Disconnect all websocket clients of a plugin (forces reconnection). |
| `clear_console` | Clear a plugin device's console buffer. |

### Devices

| Tool | Purpose |
|---|---|
| `list_devices` | All devices. Filter by interface / type / name substring. |
| `get_device` | Snapshot every state property on a device. |
| `call_device_method` | Invoke a method on a device (`turnOn`, `setBrightness`, `getSettings`, …). |

### Logs & alerts

| Tool | Purpose |
|---|---|
| `get_logs` | Retained server logs (~48 h). Filter by component, level, `sinceMs`. |
| `clear_logs` | Clear the server-side log buffer. |
| `list_alerts` | Persisted alerts (plugin crashes, warnings). |
| `remove_alert` | Remove a single alert by id. |
| `clear_alerts` | Remove all alerts. |

### Server administration

| Tool | Purpose |
|---|---|
| `get_server_info` | Scrypted version + `SCRYPTED_*` environment variables. |
| `restart_server` | Restart the Scrypted server. The MCP connection drops. |
| `update_server` | Trigger a server update (webhook or `.update` file + restart). |
| `get_dotenv` | Read the contents of the Scrypted `.env` file. |
| `set_dotenv` | Overwrite the Scrypted `.env` file (verbatim — include all keys). |

### Users

| Tool | Purpose |
|---|---|
| `list_users` | All Scrypted user accounts (username + admin flag). |
| `add_user` | Create a user. Omit `aclId` to create an admin. |
| `remove_user` | Delete a user by username. |

### Network

| Tool | Purpose |
|---|---|
| `get_local_addresses` | Configured local addresses / interface names. |
| `set_local_addresses` | Replace local addresses. Pass interface names (`en0`) or IPs. |
| `get_external_addresses` | External (publicly reachable) addresses for a plugin endpoint. |
| `set_external_addresses` | Replace external addresses for a plugin endpoint. |
| `get_cors` | CORS origin allowlist for a plugin endpoint. |
| `set_cors` | Replace the CORS origin allowlist for a plugin endpoint. |

### Cluster

| Tool | Purpose |
|---|---|
| `list_cluster_workers` | Registered cluster workers (id, name, labels, mode, address, fork count). |

### Backup & restore

| Tool | Purpose |
|---|---|
| `create_backup` | Snapshot the Scrypted database to a ZIP at an absolute path on the MCP host. |
| `restore_backup` | Restore from a backup ZIP. **Destructive** — wipes the database and installed plugin files. |

`restore_backup` is gated three ways before it runs:

1. The `confirm` argument must equal the exact string `RESTORE FROM BACKUP`.
2. The MCP client must support [elicitation](https://modelcontextprotocol.io/specification/server/elicitation) and the user must explicitly select `RESTORE` in the confirmation dialog. Without elicitation support the tool refuses to run.
3. The tool is annotated `destructiveHint: true` so well-behaved clients require user approval before the call.

The MCP connection drops when the server restarts at the end of a successful restore.

## Install & configure

```bash
npm install
npm run build
node dist/index.js setup
```

The `setup` command prompts for the Scrypted URL (default `https://localhost:10443`), username, and password (hidden), and writes them to `~/.scrypted-mcp/config.json` with mode 0600.

Env vars override the saved config when set, so CI or one-off remote tests can use:

```bash
SCRYPTED_URL=https://other:10443 SCRYPTED_USERNAME=admin SCRYPTED_PASSWORD=… node dist/index.js
```

By default, self-signed TLS certificates are accepted (matches typical Scrypted setups). Set `SCRYPTED_TLS_STRICT=1` to require a valid cert chain.

## Use with Claude Desktop

After running `setup`, add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scrypted": {
      "command": "node",
      "args": ["/absolute/path/to/scrypted-mcp/dist/index.js"]
    }
  }
}
```

The daemon picks up credentials from `~/.scrypted-mcp/config.json` automatically.

## Use with Claude Code

```bash
npm run build
claude mcp add scrypted --scope=user -- node "$(pwd)/dist/index.js"
```

## Develop

```bash
npm run dev    # tsx, no build step
```
