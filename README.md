# scrypted-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Scrypted](https://scrypted.app). Lets AI assistants (Claude Desktop, Claude Code, etc.) inspect logs, manage plugins, and query devices on a running Scrypted server.

## Tools

| Tool | Purpose |
|---|---|
| `list_plugins` | All installed plugins with id / pluginId / name / type. |
| `get_plugin_info` | pid, pending RPC calls, object count for one plugin. |
| `reload_plugin` | Restart a plugin host (picks up code changes). |
| `kill_plugin` | Kill a plugin host without auto-reload. |
| `install_plugin` | Install / upgrade a plugin from npm. |
| `update_plugins` | Upgrade every installed plugin to its latest npm version. |
| `get_logs` | Retained server logs (~48 h). Filter by component, level, `sinceMs`. |
| `clear_logs` | Clear the server-side log buffer. |
| `list_devices` | All devices. Filter by interface / type / name substring. |
| `get_device` | Snapshot every state property on a device. |
| `call_device_method` | Invoke a method on a device (`turnOn`, `setBrightness`, `getSettings`, …). |

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
claude mcp add scrypted -- node "$(pwd)/dist/index.js"
```

## Develop

```bash
npm run dev    # tsx, no build step
```
