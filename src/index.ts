#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { runSetup } from './setup.js';
import {
    clearAlerts,
    clearAlertsInput,
    listAlerts,
    listAlertsInput,
    removeAlert,
    removeAlertInput,
} from './tools/alerts.js';
import { createBackup, createBackupInput, makeRestoreBackupHandler, restoreBackupInput } from './tools/backup.js';
import { listClusterWorkers, listClusterWorkersInput } from './tools/cluster.js';
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
    getCors,
    getCorsInput,
    getExternalAddresses,
    getExternalAddressesInput,
    getLocalAddresses,
    getLocalAddressesInput,
    setCors,
    setCorsInput,
    setExternalAddresses,
    setExternalAddressesInput,
    setLocalAddresses,
    setLocalAddressesInput,
} from './tools/network.js';
import {
    clearConsole,
    clearConsoleInput,
    disconnectClients,
    disconnectClientsInput,
    getIdForNativeId,
    getIdForNativeIdInput,
    getPluginInfo,
    getPluginInfoInput,
    getStorage,
    getStorageInput,
    installPlugin,
    installPluginInput,
    killPlugin,
    killPluginInput,
    listPlugins,
    listPluginsInput,
    npmInfo,
    npmInfoInput,
    reloadPlugin,
    reloadPluginInput,
    renameDeviceId,
    renameDeviceIdInput,
    setMixins,
    setMixinsInput,
    setStorage,
    setStorageInput,
    updatePlugins,
    updatePluginsInput,
} from './tools/plugins.js';
import {
    getDotEnv,
    getDotEnvInput,
    getServerInfo,
    getServerInfoInput,
    restartServer,
    restartServerInput,
    setDotEnv,
    setDotEnvInput,
    updateServer,
    updateServerInput,
} from './tools/server.js';
import { addUser, addUserInput, listUsers, listUsersInput, removeUser, removeUserInput } from './tools/users.js';

// `scrypted-mcp setup` runs the interactive credential wizard. Anything else (no args, or
// the daemon being launched by Claude Desktop) falls through to the MCP stdio server.
if (process.argv[2] === 'setup') {
    await runSetup();
    process.exit(0);
}

const server = new McpServer(
    { name: 'scrypted-mcp', version: '0.2.1' },
    {
        instructions: [
            'This MCP server controls a running Scrypted server (https://scrypted.app).',
            'Inspect: list_plugins / get_plugin_info / get_logs / get_server_info.',
            'Devices: list_devices / get_device / call_device_method (any RPC method).',
            'Plugin lifecycle: reload_plugin (after code changes), install_plugin, update_plugins, kill_plugin.',
            'Server admin: restart_server, update_server, get_dotenv / set_dotenv, list_users / add_user / remove_user.',
            'Network: get_local_addresses / set_local_addresses, get_cors / set_cors.',
            'Alerts and cluster: list_alerts, list_cluster_workers.',
            'Backup: create_backup writes a ZIP; restore_backup is destructive and triggers a user confirmation prompt.',
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
    'npm_info',
    {
        description:
            'Query npmjs.org via the Scrypted server. Pass a package name (e.g. "scrypted-kasa") for full metadata, or "-/v1/search?text=keywords:scrypted-plugin" to discover available Scrypted plugins. Returns the raw npm registry response.',
        inputSchema: npmInfoInput.shape,
        annotations: {
            title: 'Query npm registry',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: true,
        },
    },
    wrap(npmInfo),
);

server.registerTool(
    'rename_device_id',
    {
        description:
            'Rename a Scrypted device id. Briefly kills the owning plugin host while it rewrites references — expect a short offline window.',
        inputSchema: renameDeviceIdInput.shape,
    },
    wrap(renameDeviceId),
);

server.registerTool(
    'set_mixins',
    {
        description:
            "Replace the list of mixins on a device. The provided array fully replaces the device's current mixins — read get_device first if you only want to add or remove one. Mixin ids are device ids of plugins like prebuffer, snapshot, REST, etc.",
        inputSchema: setMixinsInput.shape,
        annotations: {
            title: 'Set device mixins',
            destructiveHint: true,
            idempotentHint: true,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(setMixins),
);

server.registerTool(
    'get_storage',
    {
        description: "Read a plugin device's persistent KV storage (string keys, string values).",
        inputSchema: getStorageInput.shape,
        annotations: {
            title: 'Get device storage',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false,
        },
    },
    wrap(getStorage),
);

server.registerTool(
    'set_storage',
    {
        description:
            "Replace a plugin device's persistent KV storage. The provided map fully replaces existing storage — read get_storage first if you only want to change one key.",
        inputSchema: setStorageInput.shape,
        annotations: {
            title: 'Set device storage',
            destructiveHint: true,
            idempotentHint: true,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(setStorage),
);

server.registerTool(
    'get_id_for_native_id',
    {
        description:
            "Reverse-lookup a Scrypted device id from a plugin's internal nativeId. Useful when reading logs that reference nativeIds. Returns { id: null } if no match.",
        inputSchema: getIdForNativeIdInput.shape,
        annotations: {
            title: 'Resolve nativeId to device id',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false,
        },
    },
    wrap(getIdForNativeId),
);

server.registerTool(
    'disconnect_clients',
    {
        description: 'Disconnect all websocket clients of a plugin (forces reconnection).',
        inputSchema: disconnectClientsInput.shape,
        annotations: {
            title: 'Disconnect plugin clients',
            destructiveHint: false,
            idempotentHint: true,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(disconnectClients),
);

server.registerTool(
    'clear_console',
    {
        description: "Clear a plugin device's console buffer. Useful for setting up a clean repro window.",
        inputSchema: clearConsoleInput.shape,
        annotations: {
            title: 'Clear device console',
            destructiveHint: false,
            idempotentHint: true,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(clearConsole),
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
    'list_alerts',
    {
        description:
            'List Scrypted alerts (newest first). Alerts are persisted notices like plugin crashes or warnings.',
        inputSchema: listAlertsInput.shape,
    },
    wrap(listAlerts),
);

server.registerTool(
    'remove_alert',
    {
        description: 'Remove a single alert by id (use the `id` field from list_alerts).',
        inputSchema: removeAlertInput.shape,
    },
    wrap(removeAlert),
);

server.registerTool(
    'clear_alerts',
    {
        description: 'Remove all alerts. Returns { cleared: true } on success.',
        inputSchema: clearAlertsInput.shape,
    },
    wrap(clearAlerts),
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

server.registerTool(
    'get_server_info',
    {
        description: 'Get Scrypted server version and SCRYPTED_* environment variables.',
        inputSchema: getServerInfoInput.shape,
    },
    wrap(getServerInfo),
);

server.registerTool(
    'restart_server',
    {
        description: 'Restart the Scrypted server. The current MCP connection will drop and need to reconnect.',
        inputSchema: restartServerInput.shape,
    },
    wrap(restartServer),
);

server.registerTool(
    'update_server',
    {
        description:
            'Trigger a Scrypted server update. Honors SCRYPTED_WEBHOOK_UPDATE if set, otherwise writes .update and restarts.',
        inputSchema: updateServerInput.shape,
    },
    wrap(updateServer),
);

server.registerTool(
    'get_dotenv',
    {
        description: 'Read the contents of the Scrypted .env file. Returns empty content if the file does not exist.',
        inputSchema: getDotEnvInput.shape,
    },
    wrap(getDotEnv),
);

server.registerTool(
    'set_dotenv',
    {
        description:
            'Overwrite the Scrypted .env file. The provided content is written verbatim — include all keys you want to keep.',
        inputSchema: setDotEnvInput.shape,
    },
    wrap(setDotEnv),
);

server.registerTool(
    'list_users',
    {
        description: 'List Scrypted user accounts (username + admin flag).',
        inputSchema: listUsersInput.shape,
    },
    wrap(listUsers),
);

server.registerTool(
    'add_user',
    {
        description: 'Create a new Scrypted user. Omit aclId to create an admin.',
        inputSchema: addUserInput.shape,
    },
    wrap(addUser),
);

server.registerTool(
    'remove_user',
    {
        description: 'Delete a Scrypted user by username.',
        inputSchema: removeUserInput.shape,
    },
    wrap(removeUser),
);

server.registerTool(
    'get_local_addresses',
    {
        description: 'Get the configured local addresses / interface names that Scrypted advertises.',
        inputSchema: getLocalAddressesInput.shape,
    },
    wrap(getLocalAddresses),
);

server.registerTool(
    'set_local_addresses',
    {
        description: 'Replace the configured local addresses. Pass interface names ("en0") or IPs.',
        inputSchema: setLocalAddressesInput.shape,
    },
    wrap(setLocalAddresses),
);

server.registerTool(
    'get_external_addresses',
    {
        description: 'Get the configured external (publicly reachable) addresses for a plugin endpoint.',
        inputSchema: getExternalAddressesInput.shape,
    },
    wrap(getExternalAddresses),
);

server.registerTool(
    'set_external_addresses',
    {
        description: 'Replace the configured external addresses for a plugin endpoint.',
        inputSchema: setExternalAddressesInput.shape,
    },
    wrap(setExternalAddresses),
);

server.registerTool(
    'get_cors',
    {
        description: 'Get the CORS origin allowlist for a plugin endpoint.',
        inputSchema: getCorsInput.shape,
    },
    wrap(getCors),
);

server.registerTool(
    'set_cors',
    {
        description: 'Replace the CORS origin allowlist for a plugin endpoint.',
        inputSchema: setCorsInput.shape,
    },
    wrap(setCors),
);

server.registerTool(
    'list_cluster_workers',
    {
        description: 'List registered Scrypted cluster worker nodes (id, name, labels, mode, address, fork count).',
        inputSchema: listClusterWorkersInput.shape,
    },
    wrap(listClusterWorkers),
);

server.registerTool(
    'create_backup',
    {
        description:
            'Snapshot the Scrypted database to a ZIP file at the given absolute path on the MCP host. Overwrites any existing file at that path.',
        inputSchema: createBackupInput.shape,
        annotations: {
            title: 'Create Scrypted backup',
            destructiveHint: true,
            idempotentHint: false,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(createBackup),
);

server.registerTool(
    'restore_backup',
    {
        description: [
            'Restore the Scrypted database from a backup ZIP. DESTRUCTIVE: kills the server, wipes the existing database',
            'and installed plugin files, extracts the backup, then restarts. Plugins reinstall from npm on first boot.',
            'Three gates: (1) the `confirm` argument must equal "RESTORE FROM BACKUP" verbatim, (2) the MCP client must',
            'support elicitation and the user must accept the in-app confirmation prompt, (3) the agent must surface',
            'the inputPath and impact to the user before invoking. The MCP connection will drop on success.',
        ].join(' '),
        inputSchema: restoreBackupInput.shape,
        annotations: {
            title: 'Restore Scrypted backup',
            destructiveHint: true,
            idempotentHint: false,
            readOnlyHint: false,
            openWorldHint: false,
        },
    },
    wrap(makeRestoreBackupHandler(server)),
);

const transport = new StdioServerTransport();
await server.connect(transport);
