#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { runSetup } from './setup.js';
import {
    callDeviceMethod,
    callDeviceMethodInput,
    getDevice,
    getDeviceInput,
    listDevices,
    listDevicesInput,
} from './tools/devices.js';
import { clearLogs, clearLogsInput, getLogs, getLogsInput } from './tools/logs.js';
import {
    getPluginInfo,
    getPluginInfoInput,
    installPlugin,
    installPluginInput,
    killPlugin,
    killPluginInput,
    listPlugins,
    listPluginsInput,
    reloadPlugin,
    reloadPluginInput,
    updatePlugins,
    updatePluginsInput,
} from './tools/plugins.js';

// `scrypted-mcp setup` runs the interactive credential wizard. Anything else (no args, or
// the daemon being launched by Claude Desktop) falls through to the MCP stdio server.
if (process.argv[2] === 'setup') {
    await runSetup();
    process.exit(0);
}

const server = new McpServer(
    { name: 'scrypted-mcp', version: '0.1.0' },
    {
        instructions: [
            'This MCP server controls a running Scrypted server (https://scrypted.app).',
            'Use list_plugins / get_plugin_info / get_logs to inspect a plugin.',
            'Use list_devices / get_device / call_device_method to query or control devices.',
            'Use reload_plugin after modifying plugin code in development.',
            'Logs are retained ~48h; pass `sinceMs` to focus on a recent window.',
        ].join(' '),
    },
);

// Wrap each tool handler so any thrown error becomes a structured MCP error response
// instead of crashing the stdio server.
function wrap<TArgs, TResult>(handler: (args: TArgs) => Promise<TResult>) {
    return async (args: TArgs) => {
        try {
            const result = await handler(args);
            return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
        } catch (e: any) {
            return {
                isError: true,
                content: [{ type: 'text' as const, text: `error: ${e?.message ?? String(e)}` }],
            };
        }
    };
}

server.registerTool(
    'list_plugins',
    {
        description: 'List installed Scrypted plugins (id, npm pluginId, name, type).',
        inputSchema: listPluginsInput.shape,
    },
    wrap(listPlugins),
);

server.registerTool(
    'get_plugin_info',
    {
        description: 'Inspect a plugin: pid, pending RPC calls, object count, etc.',
        inputSchema: getPluginInfoInput.shape,
    },
    wrap(getPluginInfo),
);

server.registerTool(
    'reload_plugin',
    {
        description: 'Restart a plugin host process (preserves state, picks up code changes).',
        inputSchema: reloadPluginInput.shape,
    },
    wrap(reloadPlugin),
);

server.registerTool(
    'kill_plugin',
    {
        description: 'Kill a plugin host without auto-reload. Use sparingly.',
        inputSchema: killPluginInput.shape,
    },
    wrap(killPlugin),
);

server.registerTool(
    'install_plugin',
    {
        description: 'Install (or upgrade) a plugin from npm. Returns the plugin device id.',
        inputSchema: installPluginInput.shape,
    },
    wrap(installPlugin),
);

server.registerTool(
    'update_plugins',
    {
        description: 'Check all installed plugins against npm and upgrade any that are outdated.',
        inputSchema: updatePluginsInput.shape,
    },
    wrap(updatePlugins),
);

server.registerTool(
    'get_logs',
    {
        description: 'Fetch retained server-side logs. Filter by component (substring match), level, sinceMs.',
        inputSchema: getLogsInput.shape,
    },
    wrap(getLogs),
);

server.registerTool(
    'clear_logs',
    {
        description: 'Clear the server-side log buffer. Returns { cleared: true } on success.',
        inputSchema: clearLogsInput.shape,
    },
    wrap(clearLogs),
);

server.registerTool(
    'list_devices',
    {
        description: 'List devices on the Scrypted server. Filter by interface, type, or name substring.',
        inputSchema: listDevicesInput.shape,
    },
    wrap(listDevices),
);

server.registerTool(
    'get_device',
    {
        description: 'Get a snapshot of every state property on a device.',
        inputSchema: getDeviceInput.shape,
    },
    wrap(getDevice),
);

server.registerTool(
    'call_device_method',
    {
        description:
            'Invoke a method on a device (e.g. turnOn, setBrightness, getSettings). Returns the JSON-serialized result.',
        inputSchema: callDeviceMethodInput.shape,
    },
    wrap(callDeviceMethod),
);

const transport = new StdioServerTransport();
await server.connect(transport);
