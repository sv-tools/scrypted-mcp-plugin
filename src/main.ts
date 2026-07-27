import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import sdk, {
    ScryptedDeviceBase,
    ScryptedInterface,
    type HttpRequest,
    type HttpRequestHandler,
    type HttpResponse,
    type Setting,
    type SettingValue,
    type Settings,
} from '@scrypted/sdk';
import { fromWebResponse, sendJson, sendText, toWebRequest } from './http-bridge';
import {
    ACCESS_TOKEN_TTL_MAX_SEC,
    ACCESS_TOKEN_TTL_MIN_SEC,
    DEFAULT_ACCESS_TOKEN_TTL_SEC,
    DEFAULT_REFRESH_TOKEN_TTL_SEC,
    OAuthService,
    REFRESH_TOKEN_TTL_MAX_SEC,
    REFRESH_TOKEN_TTL_MIN_SEC,
} from './oauth';
import {
    clearAlerts,
    clearAlertsInput,
    listAlerts,
    listAlertsInput,
    removeAlert,
    removeAlertInput,
} from './tools/alerts';
import { createBackup, createBackupInput, makeRestoreBackupHandler, restoreBackupInput } from './tools/backup';
import { listClusterWorkers, listClusterWorkersInput } from './tools/cluster';
import {
    callDeviceMethod,
    callDeviceMethodInput,
    getDevice,
    getDeviceInput,
    listDevices,
    listDevicesInput,
} from './tools/devices';
import { clearLogs, clearLogsInput, getLogs, getLogsInput } from './tools/logs';
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
} from './tools/network';
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
} from './tools/plugins';
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
} from './tools/server';
import { addUser, addUserInput, listUsers, listUsersInput, removeUser, removeUserInput } from './tools/users';

// Wrapper around tool handlers. Two responsibilities:
//   1. Catch thrown errors and surface them as structured MCP error responses (`isError: true`).
//   2. For most tools, JSON-stringify the return value so the LLM gets a single text block.
//      Tools that need to return multi-block content (like backup with its base64 ZIP blob)
//      opt out via `{ rawContent: true }` and return the full MCP `content` array themselves.
//
// We dropped the auto-retry-on-transient-disconnect path that the stdio version had: now
// that we run inside the Scrypted process there's no socket between us and the runtime to
// drop, so transient errors don't exist by definition.
function wrap<TArgs, TResult>(handler: (args: TArgs) => Promise<TResult>, opts: { rawContent?: boolean } = {}) {
    return async (args: TArgs) => {
        try {
            const result = await handler(args);
            if (opts.rawContent) return result as any;
            // A void/undefined handler result makes JSON.stringify return the JS value
            // `undefined` (not a string), which yields { text: undefined } and fails the MCP
            // content union schema. Coerce to null so we always emit a valid text block.
            return { content: [{ type: 'text' as const, text: JSON.stringify(result ?? null, null, 2) }] };
        } catch (e: any) {
            return {
                isError: true,
                content: [{ type: 'text' as const, text: `error: ${e?.message ?? String(e)}` }],
            };
        }
    };
}

// Construct a fresh McpServer with the full tool surface. We build one per Streamable HTTP
// session because Server.connect(transport) binds a server to one transport, and each
// session has its own transport instance. Session lifetime is short — until the client
// closes the connection or sends DELETE — so the per-session allocation cost is fine.
//
// `getMaxRestoreBytes` is plumbed through so tools that need access to plugin settings
// (currently just restore_backup) can read the live value without coupling to the plugin
// instance directly.
function createMcpServer(getMaxRestoreBytes: () => number): McpServer {
    const server = new McpServer(
        { name: 'scrypted-mcp', version: '1.0.8' },
        {
            instructions: [
                'This MCP server runs inside a Scrypted plugin and controls the same Scrypted server (https://scrypted.app).',
                'Inspect: list_plugins / get_plugin_info / get_logs / get_server_info / npm_info.',
                'Devices: list_devices / get_device / call_device_method (any RPC method); resolve nativeIds with get_id_for_native_id.',
                'Plugin lifecycle: reload_plugin (after code changes), install_plugin, update_plugins, kill_plugin, disconnect_clients, clear_console.',
                'Device config: get_storage / set_storage (KV storage), set_mixins, rename_device_id.',
                'Server admin: restart_server, update_server, get_dotenv / set_dotenv, list_users / add_user / remove_user.',
                'Network: get_local_addresses / set_local_addresses, get_external_addresses / set_external_addresses, get_cors / set_cors.',
                'Alerts and cluster: list_alerts / remove_alert / clear_alerts, clear_logs, list_cluster_workers.',
                'Backup: create_backup returns the ZIP inline as a base64 blob; restore_backup takes a base64 blob input and is destructive (triggers a user confirmation prompt).',
                'Tool annotations are set: prefer readOnly tools freely; destructive tools (set_*, clear_*, remove_*, kill_*, restart/update_server, restore_backup) should be surfaced to the user first.',
                'Logs are retained ~48h; pass `sinceMs` to focus on a recent window.',
            ].join(' '),
        },
    );

    server.registerTool(
        'list_plugins',
        {
            description:
                'List installed Scrypted plugins. Returns for each: Scrypted device `id`, npm `pluginId` (the id passed to reload_plugin / get_plugin_info / kill_plugin), name, and type.',
            inputSchema: listPluginsInput.shape,
            annotations: {
                title: 'List plugins',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(listPlugins),
    );

    server.registerTool(
        'get_plugin_info',
        {
            description: 'Inspect a plugin: pid, pending RPC calls, object count, etc.',
            inputSchema: getPluginInfoInput.shape,
            annotations: {
                title: 'Get plugin info',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getPluginInfo),
    );

    server.registerTool(
        'reload_plugin',
        {
            description: 'Restart a plugin host process (preserves state, picks up code changes).',
            inputSchema: reloadPluginInput.shape,
            annotations: {
                title: 'Reload plugin',
                destructiveHint: false,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(reloadPlugin),
    );

    server.registerTool(
        'kill_plugin',
        {
            description:
                'Kill a plugin host without auto-reload — the plugin stays down until you call reload_plugin or the server restarts. Prefer reload_plugin unless you specifically need it stopped.',
            inputSchema: killPluginInput.shape,
            annotations: {
                title: 'Kill plugin',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(killPlugin),
    );

    server.registerTool(
        'install_plugin',
        {
            description: 'Install (or upgrade) a plugin from npm. Returns the plugin device id.',
            inputSchema: installPluginInput.shape,
            annotations: {
                title: 'Install plugin',
                destructiveHint: false,
                idempotentHint: false,
                readOnlyHint: false,
                openWorldHint: true,
            },
        },
        wrap(installPlugin),
    );

    server.registerTool(
        'update_plugins',
        {
            description: 'Check all installed plugins against npm and upgrade any that are outdated.',
            inputSchema: updatePluginsInput.shape,
            annotations: {
                title: 'Update plugins',
                destructiveHint: false,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: true,
            },
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
            annotations: {
                title: 'Rename device id',
                destructiveHint: true,
                idempotentHint: false,
                readOnlyHint: false,
                openWorldHint: false,
            },
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
                destructiveHint: true,
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
            description:
                'Fetch retained server-side logs (newest first). Filter by component (substring match), level, sinceMs. Results are capped (`truncated: true` when more matched) — narrow the filters or raise `limit` to see the rest.',
            inputSchema: getLogsInput.shape,
            annotations: {
                title: 'Get logs',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getLogs),
    );

    server.registerTool(
        'clear_logs',
        {
            description: 'Clear the server-side log buffer. Returns { cleared: true } on success.',
            inputSchema: clearLogsInput.shape,
            annotations: {
                title: 'Clear logs',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(clearLogs),
    );

    server.registerTool(
        'list_alerts',
        {
            description:
                'List Scrypted alerts (newest first). Alerts are persisted notices like plugin crashes or warnings. Results are capped (`truncated: true` when more matched) — raise `limit` to see the rest.',
            inputSchema: listAlertsInput.shape,
            annotations: {
                title: 'List alerts',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(listAlerts),
    );

    server.registerTool(
        'remove_alert',
        {
            description: 'Remove a single alert by id (use the `id` field from list_alerts).',
            inputSchema: removeAlertInput.shape,
            annotations: {
                title: 'Remove alert',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(removeAlert),
    );

    server.registerTool(
        'clear_alerts',
        {
            description: 'Remove all alerts. Returns { cleared: true } on success.',
            inputSchema: clearAlertsInput.shape,
            annotations: {
                title: 'Clear alerts',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(clearAlerts),
    );

    server.registerTool(
        'list_devices',
        {
            description: 'List devices on the Scrypted server. Filter by interface, type, or name substring.',
            inputSchema: listDevicesInput.shape,
            annotations: {
                title: 'List devices',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(listDevices),
    );

    server.registerTool(
        'get_device',
        {
            description:
                'Get a snapshot of every state property on a device. Returns the full state map, which can be large for cameras; the `interfaces` array tells you which methods call_device_method can invoke.',
            inputSchema: getDeviceInput.shape,
            annotations: {
                title: 'Get device',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getDevice),
    );

    server.registerTool(
        'call_device_method',
        {
            description:
                "Invoke a method on a device (e.g. turnOn, setBrightness, getSettings). The available methods follow from the device's `interfaces` — call get_device first if unsure. May read or mutate depending on the method. Returns the JSON-serialized result.",
            inputSchema: callDeviceMethodInput.shape,
            annotations: {
                title: 'Call device method',
            },
        },
        wrap(callDeviceMethod),
    );

    server.registerTool(
        'get_server_info',
        {
            description: 'Get Scrypted server version and SCRYPTED_* environment variables.',
            inputSchema: getServerInfoInput.shape,
            annotations: {
                title: 'Get server info',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getServerInfo),
    );

    server.registerTool(
        'restart_server',
        {
            description: 'Restart the Scrypted server. The current MCP connection will drop and need to reconnect.',
            inputSchema: restartServerInput.shape,
            annotations: {
                title: 'Restart server',
                destructiveHint: true,
                idempotentHint: false,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(restartServer),
    );

    server.registerTool(
        'update_server',
        {
            description:
                'Trigger a Scrypted server update. Honors SCRYPTED_WEBHOOK_UPDATE if set, otherwise writes .update and restarts. Returns immediately; the server restarts asynchronously and the MCP connection will drop, like restart_server.',
            inputSchema: updateServerInput.shape,
            annotations: {
                title: 'Update server',
                destructiveHint: true,
                idempotentHint: false,
                readOnlyHint: false,
                openWorldHint: true,
            },
        },
        wrap(updateServer),
    );

    server.registerTool(
        'get_dotenv',
        {
            description:
                'Read the contents of the Scrypted .env file. Returns empty content if the file does not exist.',
            inputSchema: getDotEnvInput.shape,
            annotations: {
                title: 'Get .env',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getDotEnv),
    );

    server.registerTool(
        'set_dotenv',
        {
            description:
                'Overwrite the Scrypted .env file. The provided content is written verbatim — include all keys you want to keep.',
            inputSchema: setDotEnvInput.shape,
            annotations: {
                title: 'Set .env',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(setDotEnv),
    );

    server.registerTool(
        'list_users',
        {
            description: 'List Scrypted user accounts (username + admin flag).',
            inputSchema: listUsersInput.shape,
            annotations: {
                title: 'List users',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(listUsers),
    );

    server.registerTool(
        'add_user',
        {
            description: 'Create a new Scrypted user. Omit aclId to create an admin.',
            inputSchema: addUserInput.shape,
            annotations: {
                title: 'Add user',
                destructiveHint: false,
                idempotentHint: false,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(addUser),
    );

    server.registerTool(
        'remove_user',
        {
            description: 'Delete a Scrypted user by username.',
            inputSchema: removeUserInput.shape,
            annotations: {
                title: 'Remove user',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(removeUser),
    );

    server.registerTool(
        'get_local_addresses',
        {
            description: 'Get the configured local addresses / interface names that Scrypted advertises.',
            inputSchema: getLocalAddressesInput.shape,
            annotations: {
                title: 'Get local addresses',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getLocalAddresses),
    );

    server.registerTool(
        'set_local_addresses',
        {
            description: 'Replace the configured local addresses. Pass interface names ("en0") or IPs.',
            inputSchema: setLocalAddressesInput.shape,
            annotations: {
                title: 'Set local addresses',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(setLocalAddresses),
    );

    server.registerTool(
        'get_external_addresses',
        {
            description: 'Get the configured external (publicly reachable) addresses for a plugin endpoint.',
            inputSchema: getExternalAddressesInput.shape,
            annotations: {
                title: 'Get external addresses',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getExternalAddresses),
    );

    server.registerTool(
        'set_external_addresses',
        {
            description: 'Replace the configured external addresses for a plugin endpoint.',
            inputSchema: setExternalAddressesInput.shape,
            annotations: {
                title: 'Set external addresses',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(setExternalAddresses),
    );

    server.registerTool(
        'get_cors',
        {
            description: 'Get the CORS origin allowlist for a plugin endpoint.',
            inputSchema: getCorsInput.shape,
            annotations: {
                title: 'Get CORS allowlist',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(getCors),
    );

    server.registerTool(
        'set_cors',
        {
            description: 'Replace the CORS origin allowlist for a plugin endpoint.',
            inputSchema: setCorsInput.shape,
            annotations: {
                title: 'Set CORS allowlist',
                destructiveHint: true,
                idempotentHint: true,
                readOnlyHint: false,
                openWorldHint: false,
            },
        },
        wrap(setCors),
    );

    server.registerTool(
        'list_cluster_workers',
        {
            description: 'List registered Scrypted cluster worker nodes (id, name, labels, mode, address, fork count).',
            inputSchema: listClusterWorkersInput.shape,
            annotations: {
                title: 'List cluster workers',
                readOnlyHint: true,
                idempotentHint: true,
                openWorldHint: false,
            },
        },
        wrap(listClusterWorkers),
    );

    server.registerTool(
        'create_backup',
        {
            description:
                'Snapshot the Scrypted database. Returns the ZIP inline as a base64-encoded resource (plus a JSON summary with byte count + sha256) for the agent to save locally. Nothing is written to the Scrypted host filesystem.',
            inputSchema: createBackupInput.shape,
            annotations: {
                title: 'Create Scrypted backup',
                destructiveHint: false,
                idempotentHint: false,
                readOnlyHint: true,
                openWorldHint: false,
            },
        },
        // rawContent: createBackup returns a multi-block MCP content array (text summary +
        // base64 resource), not a JSON-serializable result. The wrapper would otherwise
        // wrap that whole structure in another text block.
        wrap(createBackup, { rawContent: true }),
    );

    server.registerTool(
        'restore_backup',
        {
            description: [
                'Restore the Scrypted database from a base64-encoded backup ZIP. DESTRUCTIVE: kills the server, wipes the existing database',
                'and installed plugin files, extracts the backup, then restarts. Plugins reinstall from npm on first boot.',
                'Three gates: (1) the `confirm` argument must equal "RESTORE FROM BACKUP" verbatim, (2) the MCP client must',
                'support elicitation and the user must accept the in-app confirmation prompt, (3) the agent must surface',
                'the size and impact to the user before invoking. The MCP connection will drop on success.',
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
        wrap(makeRestoreBackupHandler(server, getMaxRestoreBytes)),
    );

    return server;
}

// Plugin entrypoint. One process-wide instance, registered as the @scrypted/mcp plugin's
// HttpRequestHandler. Owns:
//   - the OAuth AS state (signing key, DCR registrations) — persisted in plugin storage
//   - the live MCP session map keyed by Mcp-Session-Id
//   - inbound request dispatch to the right handler
// Idle session reaper. The Streamable HTTP transport only fires onsessionclosed when the
// client sends DELETE or its socket faults — clients that just stop calling leak entries
// indefinitely. We stamp lastSeen on every request and sweep periodically. The TTL matches
// the access-token lifetime: any session idle for that long either has an expired token (so
// the next request would re-auth and create a fresh session anyway) or is genuinely
// abandoned. The sweep interval is short enough to keep the map bounded in practice without
// burning CPU.
const SESSION_IDLE_TTL_MS = 60 * 60 * 1000; // 1h
const SESSION_SWEEP_INTERVAL_MS = 10 * 60 * 1000; // 10min

// Plugin settings. Persisted in plugin storage (so they survive reloads) under the keys
// declared here; surfaced via getSettings() / putSetting() in the Scrypted UI.
const STORAGE_KEY_DCR_MAX_CLIENTS = 'settings.dcr_max_clients';
const STORAGE_KEY_ACCESS_TOKEN_TTL_SEC = 'settings.access_token_ttl_sec';
const STORAGE_KEY_REFRESH_TOKEN_TTL_SEC = 'settings.refresh_token_ttl_sec';
const STORAGE_KEY_MAX_RESTORE_MB = 'settings.max_restore_mb';
const DEFAULT_DCR_MAX_CLIENTS = 100;
const DEFAULT_MAX_RESTORE_MB = 500;
const MIN_MAX_RESTORE_MB = 1;
const MAX_MAX_RESTORE_MB = 10240; // 10GB ceiling

// Reads a positive-integer setting from plugin storage. Returns the default when the value
// is missing, malformed, or out of range — settings should never be able to brick the
// plugin no matter what the operator typed in.
function readIntegerSetting(
    storage: Pick<Storage, 'getItem'>,
    key: string,
    def: number,
    min: number,
    max: number,
): number {
    const raw = storage.getItem(key);
    if (!raw) return def;
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n) || n < min || n > max) return def;
    return n;
}

interface SessionEntry {
    transport: WebStandardStreamableHTTPServerTransport;
    server: McpServer;
    lastSeen: number;
}

class ScryptedMcpPlugin extends ScryptedDeviceBase implements HttpRequestHandler, Settings {
    private oauth: OAuthService;
    private sessions = new Map<string, SessionEntry>();

    constructor(nativeId?: string) {
        super(nativeId);
        this.oauth = new OAuthService({
            storage: this.storage,
            console: this.console,
            getMaxClients: () => this.getDcrMaxClients(),
            getAccessTokenTtlSec: () => this.getAccessTokenTtlSec(),
            getRefreshTokenTtlSec: () => this.getRefreshTokenTtlSec(),
        });
        this.console.log('[scrypted-mcp] ready. MCP endpoint: <scrypted-host>/endpoint/<package-name>/public/mcp');
        this.console.log(
            '[scrypted-mcp] OAuth metadata at the same /public/.well-known/oauth-protected-resource path.',
        );
        setInterval(() => this.sweepIdleSessions(), SESSION_SWEEP_INTERVAL_MS).unref();
    }

    private getDcrMaxClients(): number {
        return readIntegerSetting(
            this.storage,
            STORAGE_KEY_DCR_MAX_CLIENTS,
            DEFAULT_DCR_MAX_CLIENTS,
            1,
            Number.MAX_SAFE_INTEGER,
        );
    }

    private getAccessTokenTtlSec(): number {
        return readIntegerSetting(
            this.storage,
            STORAGE_KEY_ACCESS_TOKEN_TTL_SEC,
            DEFAULT_ACCESS_TOKEN_TTL_SEC,
            ACCESS_TOKEN_TTL_MIN_SEC,
            ACCESS_TOKEN_TTL_MAX_SEC,
        );
    }

    private getRefreshTokenTtlSec(): number {
        return readIntegerSetting(
            this.storage,
            STORAGE_KEY_REFRESH_TOKEN_TTL_SEC,
            DEFAULT_REFRESH_TOKEN_TTL_SEC,
            REFRESH_TOKEN_TTL_MIN_SEC,
            REFRESH_TOKEN_TTL_MAX_SEC,
        );
    }

    private getMaxRestoreMb(): number {
        return readIntegerSetting(
            this.storage,
            STORAGE_KEY_MAX_RESTORE_MB,
            DEFAULT_MAX_RESTORE_MB,
            MIN_MAX_RESTORE_MB,
            MAX_MAX_RESTORE_MB,
        );
    }

    private getMaxRestoreBytes(): number {
        return this.getMaxRestoreMb() * 1024 * 1024;
    }

    // Read-only display: build the URL clients should connect to. Wraps the SDK's
    // getLocalEndpoint in a try/catch so a misconfigured local discovery doesn't strand the
    // Settings panel — the field just shows a placeholder if it's not available.
    //
    // Returns both schemes because Scrypted typically listens on both an HTTP and HTTPS port,
    // and the right URL depends on the client: production deployments behind a reverse proxy
    // want HTTPS; local-network clients (and many MCP debugging tools) work better over HTTP.
    private async getMcpEndpointUrl(insecure: boolean): Promise<string> {
        try {
            const base = await sdk.endpointManager.getLocalEndpoint(this.nativeId, { public: true, insecure });
            // getLocalEndpoint returns the public/ root; append our /mcp path.
            return base.endsWith('/') ? `${base}mcp` : `${base}/mcp`;
        } catch (e) {
            this.console.error('[scrypted-mcp] getMcpEndpointUrl(insecure=%s) failed:', insecure, e);
            return '(unavailable — see plugin logs)';
        }
    }

    async getSettings(): Promise<Setting[]> {
        const stats = this.oauth.getStats();
        const [endpointHttps, endpointHttp] = await Promise.all([
            this.getMcpEndpointUrl(false),
            this.getMcpEndpointUrl(true),
        ]);
        return [
            {
                key: 'mcp_endpoint_https',
                title: 'MCP endpoint URL (HTTPS)',
                description:
                    'The HTTPS URL to configure in your MCP client. Use this for production / remote clients. Self-signed certificate by default — paired with a reverse proxy in most deployments.',
                type: 'string',
                group: 'Endpoint',
                readonly: true,
                value: endpointHttps,
            },
            {
                key: 'mcp_endpoint_http',
                title: 'MCP endpoint URL (HTTP)',
                description:
                    'The plain-HTTP URL. Useful for local-network clients and debugging where the self-signed HTTPS cert is awkward. Do not expose to the internet.',
                type: 'string',
                group: 'Endpoint',
                readonly: true,
                value: endpointHttp,
            },
            {
                key: 'dcr_max_clients',
                title: 'Maximum DCR client registrations',
                description: [
                    'Cap on persisted Dynamic Client Registration entries.',
                    'When a /register request would push the total above this number,',
                    'the least-recently-used registration is evicted.',
                    'Default: ' + DEFAULT_DCR_MAX_CLIENTS + '.',
                ].join(' '),
                type: 'integer',
                group: 'Configuration',
                value: this.getDcrMaxClients(),
            },
            {
                key: 'access_token_ttl_sec',
                title: 'Access token TTL (seconds)',
                description: [
                    'Lifetime of issued JWT access tokens.',
                    'Shorter values force more frequent refreshes (tighter security);',
                    'longer values reduce auth churn.',
                    `Range ${ACCESS_TOKEN_TTL_MIN_SEC}–${ACCESS_TOKEN_TTL_MAX_SEC}, default ${DEFAULT_ACCESS_TOKEN_TTL_SEC} (1h).`,
                ].join(' '),
                type: 'integer',
                group: 'Configuration',
                range: [ACCESS_TOKEN_TTL_MIN_SEC, ACCESS_TOKEN_TTL_MAX_SEC],
                value: this.getAccessTokenTtlSec(),
            },
            {
                key: 'refresh_token_ttl_sec',
                title: 'Refresh token TTL (seconds)',
                description: [
                    'Lifetime of issued refresh tokens.',
                    'Each refresh rotates the token (single-use), so this is the upper bound on how long a stolen RT remains valid before re-auth is forced.',
                    `Range ${REFRESH_TOKEN_TTL_MIN_SEC}–${REFRESH_TOKEN_TTL_MAX_SEC}, default ${DEFAULT_REFRESH_TOKEN_TTL_SEC} (30d).`,
                ].join(' '),
                type: 'integer',
                group: 'Configuration',
                range: [REFRESH_TOKEN_TTL_MIN_SEC, REFRESH_TOKEN_TTL_MAX_SEC],
                value: this.getRefreshTokenTtlSec(),
            },
            {
                key: 'max_restore_mb',
                title: 'Max restore size (MB)',
                description: [
                    'Maximum decoded backup size that restore_backup will accept.',
                    'Bump this if your Scrypted database exceeds the default;',
                    `range ${MIN_MAX_RESTORE_MB}–${MAX_MAX_RESTORE_MB} MB, default ${DEFAULT_MAX_RESTORE_MB} MB.`,
                ].join(' '),
                type: 'integer',
                group: 'Configuration',
                range: [MIN_MAX_RESTORE_MB, MAX_MAX_RESTORE_MB],
                value: this.getMaxRestoreMb(),
            },
            {
                key: 'active_sessions',
                title: 'Active MCP sessions',
                description: 'In-memory MCP sessions currently held open. Idle sessions are reaped after 1h.',
                type: 'integer',
                group: 'Status',
                readonly: true,
                value: this.sessions.size,
            },
            {
                key: 'registered_clients',
                title: 'Registered DCR clients',
                description: 'Persisted client registrations in plugin storage.',
                type: 'integer',
                group: 'Status',
                readonly: true,
                value: stats.clients,
            },
            {
                key: 'active_refresh_tokens',
                title: 'Persisted refresh tokens',
                description: 'Refresh tokens currently in plugin storage (each has a 30-day TTL).',
                type: 'integer',
                group: 'Status',
                readonly: true,
                value: stats.refreshTokens,
            },
            {
                key: 'revoke_all',
                title: 'Revoke all tokens & disconnect clients',
                description: [
                    'DESTRUCTIVE. Drops every refresh token, deletes every DCR registration,',
                    'rotates the JWT signing key (existing access tokens stop verifying),',
                    'and closes all active MCP sessions. Every client will need to re-register',
                    'and re-authenticate.',
                ].join(' '),
                type: 'button',
                group: 'Status',
            },
        ];
    }

    async putSetting(key: string, value: SettingValue): Promise<void> {
        if (key === 'dcr_max_clients') {
            this.writeIntegerSetting(key, value, STORAGE_KEY_DCR_MAX_CLIENTS, 1, Number.MAX_SAFE_INTEGER);
        } else if (key === 'access_token_ttl_sec') {
            this.writeIntegerSetting(
                key,
                value,
                STORAGE_KEY_ACCESS_TOKEN_TTL_SEC,
                ACCESS_TOKEN_TTL_MIN_SEC,
                ACCESS_TOKEN_TTL_MAX_SEC,
            );
        } else if (key === 'refresh_token_ttl_sec') {
            this.writeIntegerSetting(
                key,
                value,
                STORAGE_KEY_REFRESH_TOKEN_TTL_SEC,
                REFRESH_TOKEN_TTL_MIN_SEC,
                REFRESH_TOKEN_TTL_MAX_SEC,
            );
        } else if (key === 'max_restore_mb') {
            this.writeIntegerSetting(key, value, STORAGE_KEY_MAX_RESTORE_MB, MIN_MAX_RESTORE_MB, MAX_MAX_RESTORE_MB);
        } else if (key === 'revoke_all') {
            const counts = await this.oauth.revokeAll();
            const closed = this.closeAllSessions();
            this.console.log(
                '[scrypted-mcp] revoke_all: dropped %d clients + %d refresh tokens, closed %d sessions, rotated signing key',
                counts.clients,
                counts.refreshTokens,
                closed,
            );
        } else if (
            key === 'mcp_endpoint_https' ||
            key === 'mcp_endpoint_http' ||
            key === 'active_sessions' ||
            key === 'registered_clients' ||
            key === 'active_refresh_tokens'
        ) {
            // Read-only fields — no-op; the UI may round-trip the value on save.
            return;
        } else {
            throw new Error(`unknown setting: ${key}`);
        }
        // Tell Scrypted the device's settings changed so the UI re-fetches via getSettings().
        // For revoke_all this also surfaces the freshly-zeroed stats.
        await this.onDeviceEvent(ScryptedInterface.Settings, undefined);
    }

    // Validate + persist an integer setting. Centralised so every numeric setting gets the
    // same range check and "must be a positive integer" error message.
    private writeIntegerSetting(key: string, value: SettingValue, storageKey: string, min: number, max: number): void {
        const n = Number(value);
        if (!Number.isFinite(n) || n < min || n > max) {
            throw new Error(`${key} must be an integer between ${min} and ${max}, got ${String(value)}`);
        }
        this.storage.setItem(storageKey, String(Math.floor(n)));
    }

    // Tear down every live MCP session. Used by the revoke_all button. The transports'
    // onclose handlers also remove from the map; we delete inline as a backstop and to
    // give an accurate count back to the caller.
    private closeAllSessions(): number {
        let closed = 0;
        for (const [sid, entry] of this.sessions) {
            try {
                entry.transport.close();
            } catch {
                // closing an already-closed transport is fine
            }
            this.sessions.delete(sid);
            closed++;
        }
        return closed;
    }

    private sweepIdleSessions(): void {
        const now = Date.now();
        for (const [sid, entry] of this.sessions) {
            if (now - entry.lastSeen <= SESSION_IDLE_TTL_MS) continue;
            // Best-effort transport teardown. The transport's onclose handler removes the
            // entry from the map, but we delete here too in case close() is a no-op or
            // throws — the goal is to bound the map regardless.
            try {
                entry.transport.close();
            } catch {
                // closing an already-closed transport is fine
            }
            this.sessions.delete(sid);
            this.console.log('[scrypted-mcp] reaped idle session sid=%s idleMs=%d', sid, now - entry.lastSeen);
        }
    }

    async onRequest(req: HttpRequest, res: HttpResponse): Promise<void> {
        try {
            // OAuth surface routes itself off the /authorize, /token, /register, .well-known
            // subpaths under this plugin's endpoint. Returns true if it claimed the request.
            if (await this.oauth.handle(req, res)) return;

            // Everything else we recognise lives on the public path under /mcp.
            const local = stripPluginPrefix(req);
            if (local === '/mcp' || local === '/mcp/') {
                await this.handleMcp(req, res);
                return;
            }

            sendText(res, 404, 'Not Found');
        } catch (e: any) {
            this.console.error('onRequest error', e);
            sendText(res, 500, `internal error: ${e?.message ?? String(e)}`);
        }
    }

    private async handleMcp(req: HttpRequest, res: HttpResponse): Promise<void> {
        const authInfo = await this.oauth.verifyBearer(req);
        if (!authInfo) {
            // Return 405 (not 401) on unauthenticated GET so the MCP TS SDK skips the
            // standalone-SSE branch and falls through to POST. The GET-401 path in
            // `client/streamableHttp.js:100` does NOT extract the WWW-Authenticate
            // `resource_metadata` URL — it just calls `auth()` blindly, which then can't
            // discover our metadata (Scrypted plugins don't own the host root, so the
            // SDK's path-aware discovery URLs all 404). The POST-401 path at
            // `streamableHttp.js:323` *does* extract the header, so we route the auth
            // bootstrap through there.
            //
            // Returning 405 on GET costs us the optional standalone OOB notification
            // stream, which we don't use anyway — elicitation flows over the per-request
            // POST SSE stream, not the GET stream.
            if ((req.method ?? 'GET').toUpperCase() === 'GET') {
                sendText(res, 405, 'Method Not Allowed');
                return;
            }
            const challenge = this.oauth.challengeFor(req);
            res.send(challenge.body, { code: challenge.status, headers: challenge.headers });
            return;
        }

        // Streamable HTTP routes by Mcp-Session-Id. A request without one and without an
        // initialize body is rejected by the transport itself (per spec), so we don't need to
        // pre-validate here — we just look up an existing session or create a new transport
        // and let the transport sort it out.
        const sessionId = req.headers?.['mcp-session-id'];
        let entry = sessionId ? this.sessions.get(sessionId) : undefined;
        if (!entry) entry = await this.createSession();
        // Stamp activity so the idle reaper doesn't evict an active session. Updates both
        // the just-created and the looked-up entry — the latter is the load-bearing case
        // (otherwise long-lived sessions would always be reaped at the TTL boundary).
        entry.lastSeen = Date.now();

        const webReq = toWebRequest(req);
        // Scrypted parses the body as text — give it back as a parsed JSON object so the
        // transport doesn't double-parse via req.json(). Empty body is fine for GET/DELETE.
        let parsedBody: unknown = undefined;
        if (req.body && (req.method ?? 'GET').toUpperCase() === 'POST') {
            try {
                parsedBody = JSON.parse(req.body);
            } catch {
                sendJson(res, 400, { error: 'invalid_json' });
                return;
            }
        }

        const webRes = await entry.transport.handleRequest(webReq, { parsedBody, authInfo });
        await fromWebResponse(webRes, res);
    }

    private async createSession(): Promise<SessionEntry> {
        // Forward-declare via a ref cell so the onsessioninitialized closure can capture
        // the entry before we've built the transport. Today the SDK invokes that callback
        // async after server.connect has committed the entry, so the original
        // `const entry = ... after transport` ordering happened to work — but a future SDK
        // change that invokes it synchronously inside the transport ctor would hit a TDZ
        // ReferenceError. The .current cell sidesteps that: the closure captures the cell
        // reference (always defined) and reads .current when invoked.
        const entryRef: { current?: SessionEntry } = {};
        const transport = new WebStandardStreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: sid => {
                // The transport calls this once it has assigned a session id — that's when we
                // commit the entry to the map so subsequent requests can find it.
                if (!entryRef.current) {
                    this.console.error('[scrypted-mcp] onsessioninitialized fired before entry was built; sid=%s', sid);
                    return;
                }
                this.sessions.set(sid, entryRef.current);
            },
            onsessionclosed: sid => {
                this.sessions.delete(sid);
            },
        });
        const server = createMcpServer(() => this.getMaxRestoreBytes());
        const entry: SessionEntry = { transport, server, lastSeen: Date.now() };
        entryRef.current = entry;
        transport.onclose = () => {
            // Belt-and-braces against the onsessionclosed callback: if the transport closes
            // for a reason other than a DELETE (e.g. process error), drop the session anyway.
            if (transport.sessionId) this.sessions.delete(transport.sessionId);
        };
        await server.connect(transport);
        return entry;
    }
}

function stripPluginPrefix(req: HttpRequest): string {
    const url = new URL(req.url ?? '/', 'http://x');
    const root = req.rootPath ?? '';
    let local = url.pathname;
    if (local.startsWith(root)) local = local.slice(root.length);
    if (!local.startsWith('/')) local = '/' + local;
    return local;
}

export default ScryptedMcpPlugin;
