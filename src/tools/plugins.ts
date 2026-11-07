import net from 'node:net';
import { z } from 'zod';
import { getComponent, systemManager } from '../scrypted';

// npm package name of this plugin. Used to refuse get_storage / set_storage against any
// device owned by us — that storage holds the OAuth signing key and DCR registrations,
// and exposing it would let any authorized caller forge tokens or hijack registered
// clients. There's no legitimate reason for an MCP tool call to read or write the MCP
// plugin's own storage, so the block is a hard reject rather than a redaction.
const SELF_PLUGIN_ID = 'scrypted-mcp';

function refuseIfOwnPlugin(deviceId: string): void {
    const dev = systemManager.getDeviceById(deviceId) as { pluginId?: string } | undefined;
    if (dev?.pluginId === SELF_PLUGIN_ID) {
        throw new Error(
            "refusing to read/write the scrypted-mcp plugin's own storage; it holds the OAuth signing key and client registrations",
        );
    }
}

interface PluginComponent {
    getPluginInfo(pluginId: string): Promise<any>;
    reload(pluginId: string): Promise<void>;
    kill(pluginId: string): Promise<void>;
    installNpm(pkg: string, version?: string): Promise<string>;
    updatePlugins(): Promise<any>;
    renameDeviceId(id: string, newId: string): Promise<void>;
    setMixins(id: string, mixins: string[]): Promise<void>;
    npmInfo(endpoint: string): Promise<any>;
    getStorage(id: string): Promise<Record<string, string>>;
    setStorage(id: string, storage: Record<string, string>): Promise<void>;
    getIdForNativeId(pluginId: string, nativeId: string | undefined): Promise<string | undefined>;
    disconnectClients(pluginId: string): Promise<void>;
    clearConsole(id: string): Promise<void>;
    // Added in Scrypted server 0.148 (unreleased as of 0.147.0). Older servers only expose the
    // console through getRemoteServicePort(pluginId, 'console').
    readConsole(id: string): Promise<string>;
    getRemoteServicePort(pluginId: string, name: string, ...args: unknown[]): Promise<[number, string | undefined]>;
}

export const listPluginsInput = z.object({});

export async function listPlugins() {
    const state = systemManager.getSystemState();
    // A plugin's controller device has type 'API' — but a more robust signal is a populated
    // `pluginId` property equal to the device's own nativeId. We surface both ids and the
    // human-readable name so the LLM can pick the right one for follow-ups.
    const plugins: Array<{ id: string; pluginId: string; name: string; type: string }> = [];
    for (const id of Object.keys(state)) {
        const dev = state[id];
        const pluginId = dev?.pluginId?.value;
        const name = dev?.name?.value;
        const type = dev?.type?.value;
        if (pluginId && name) plugins.push({ id, pluginId, name, type: type ?? '' });
    }
    plugins.sort((a, b) => a.name.localeCompare(b.name));
    return { count: plugins.length, plugins };
}

export const getPluginInfoInput = z.object({
    pluginId: z.string().describe('npm package id — the `pluginId` field from list_plugins, e.g. "scrypted-kasa".'),
});

export async function getPluginInfo(args: z.infer<typeof getPluginInfoInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    const info = await plugins.getPluginInfo(args.pluginId);
    return info ?? { error: 'plugin not found' };
}

export const reloadPluginInput = z.object({
    pluginId: z
        .string()
        .describe('npm package id to reload — the `pluginId` field from list_plugins, e.g. "scrypted-kasa".'),
});

export async function reloadPlugin(args: z.infer<typeof reloadPluginInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.reload(args.pluginId);
    return { reloaded: args.pluginId };
}

export const killPluginInput = z.object({
    pluginId: z
        .string()
        .describe('npm package id to kill — the `pluginId` field from list_plugins, e.g. "scrypted-kasa".'),
});

export async function killPlugin(args: z.infer<typeof killPluginInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.kill(args.pluginId);
    return { killed: args.pluginId };
}

export const installPluginInput = z.object({
    npmPackage: z.string().describe('npm package id, e.g. "scrypted-kasa".'),
    version: z.string().optional().describe('Version specifier; omit for latest.'),
});

export async function installPlugin(args: z.infer<typeof installPluginInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    const id = await plugins.installNpm(args.npmPackage, args.version);
    return { pluginDeviceId: id };
}

export const updatePluginsInput = z.object({});

export async function updatePlugins() {
    const plugins = await getComponent<PluginComponent>('plugins');
    // updatePlugins resolves void on the Scrypted side, so return a confirmation object —
    // a bare undefined would JSON.stringify to undefined and fail the MCP content schema.
    const result = await plugins.updatePlugins();
    return result ?? { updated: true };
}

export const renameDeviceIdInput = z.object({
    id: z.string().describe('Current Scrypted device id (the `id` field from list_devices or list_plugins).'),
    newId: z.string().describe('New device id. Must not collide with an existing device.'),
});

export async function renameDeviceId(args: z.infer<typeof renameDeviceIdInput>) {
    // Server-side this kills the owning plugin host, rewrites references in the datastore,
    // then lets it auto-restart. Expect a brief offline window for the plugin.
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.renameDeviceId(args.id, args.newId);
    return { renamed: { from: args.id, to: args.newId } };
}

export const setMixinsInput = z.object({
    id: z
        .string()
        .describe('Scrypted device id whose mixins to replace (the `id` field from list_devices or list_plugins).'),
    mixins: z
        .array(z.string())
        .describe(
            'Full replacement list of mixin device ids. REPLACES the existing list — to add or remove a single mixin, first call get_device on `id` to read the current `mixins` array, then pass the modified array here.',
        ),
});

export async function setMixins(args: z.infer<typeof setMixinsInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.setMixins(args.id, args.mixins);
    return { id: args.id, mixins: args.mixins };
}

export const npmInfoInput = z.object({
    endpoint: z
        .string()
        .describe(
            'Path appended to https://registry.npmjs.org/. Pass a package name like "scrypted-kasa" for full package metadata (versions, dist-tags, deprecation), or "-/v1/search?text=keywords:scrypted-plugin" to discover available Scrypted plugins via npm search.',
        ),
});

export async function npmInfo(args: z.infer<typeof npmInfoInput>) {
    // Server-side this is a passthrough to https://registry.npmjs.org/${endpoint}, so we
    // don't need to filter or validate — npm responds with whatever the endpoint expects.
    const plugins = await getComponent<PluginComponent>('plugins');
    return plugins.npmInfo(args.endpoint);
}

export const getStorageInput = z.object({
    id: z
        .string()
        .describe(
            'Scrypted device id whose persistent storage to read (the `id` field from list_devices or list_plugins).',
        ),
});

export async function getStorage(args: z.infer<typeof getStorageInput>) {
    refuseIfOwnPlugin(args.id);
    const plugins = await getComponent<PluginComponent>('plugins');
    const storage = await plugins.getStorage(args.id);
    return { id: args.id, storage: storage ?? {} };
}

export const setStorageInput = z.object({
    id: z
        .string()
        .describe(
            'Scrypted device id whose persistent storage to overwrite (the `id` field from list_devices or list_plugins).',
        ),
    storage: z
        .record(z.string(), z.string())
        .describe(
            "Replacement storage map (keys and values are strings). REPLACES the device's entire storage — read get_storage first if you only want to change one key.",
        ),
});

export async function setStorage(args: z.infer<typeof setStorageInput>) {
    refuseIfOwnPlugin(args.id);
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.setStorage(args.id, args.storage);
    return { id: args.id, storage: args.storage };
}

export const getIdForNativeIdInput = z.object({
    pluginId: z
        .string()
        .describe(
            'npm package id of the owning plugin — the `pluginId` field from list_plugins, e.g. "scrypted-kasa".',
        ),
    nativeId: z
        .string()
        .optional()
        .describe(
            "The plugin's internal native id for the device (often visible in logs). Omit for the plugin's root device.",
        ),
});

export async function getIdForNativeId(args: z.infer<typeof getIdForNativeIdInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    const id = await plugins.getIdForNativeId(args.pluginId, args.nativeId);
    return { id: id ?? null };
}

export const disconnectClientsInput = z.object({
    pluginId: z
        .string()
        .describe('npm package id whose websocket clients to disconnect — the `pluginId` field from list_plugins.'),
});

export async function disconnectClients(args: z.infer<typeof disconnectClientsInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.disconnectClients(args.pluginId);
    return { disconnected: args.pluginId };
}

export const clearConsoleInput = z.object({
    id: z
        .string()
        .describe(
            'Scrypted device id whose console buffer to clear (the `id` field from list_devices or list_plugins).',
        ),
});

export async function clearConsole(args: z.infer<typeof clearConsoleInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.clearConsole(args.id);
    return { cleared: args.id };
}

export const readConsoleInput = z.object({
    id: z
        .string()
        .describe('Scrypted device id whose console to read (the `id` field from list_devices or list_plugins).'),
    maxChars: z
        .number()
        .int()
        .positive()
        .max(1_000_000)
        .optional()
        .describe('Return at most this many characters from the end of the console. Default 50000.'),
});

// eslint-disable-next-line no-control-regex
const ANSI_ESCAPE = /\x1b\[[0-9;]*[A-Za-z]/g;

// Consoles can carry credentials (camera URLs with user:pass, auth headers, tokens in query
// strings or logged objects). Tool output ends up in the model's context, so redact the common
// shapes before returning, the same reasoning as get_server_info's env filtering.
const SECRET_PATTERNS: Array<[RegExp, string]> = [
    // rtsp(s)://host/<path>: stream paths often are the credential (UniFi Protect's
    // rtsps://host:7441/<token>), so keep the host for debugging and drop the path.
    [/\b(rtsps?:\/\/[^\s/'"]+\/)[^\s'"]+/gi, '$1[REDACTED]'],
    // scheme://user:password@host -> scheme://[REDACTED]@host
    [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@'],
    // Authorization: Bearer xyz / Basic xyz
    [/\b(authorization\s*[:=]\s*["']?)(?:bearer|basic|digest)?\s*[^\s"',]+/gi, '$1[REDACTED]'],
    // bare bearer tokens
    [/\b(bearer\s+)[a-z0-9._~+/-]+=*/gi, '$1[REDACTED]'],
    // token=..., password: '...', api_key=..., client_secret=...
    [
        /\b((?:access_|refresh_|id_|api_|auth_|session_)?token|password|passwd|pwd|secret|client_secret|api_?key)(["']?\s*[:=]\s*["']?)[^\s"'&,;}]+/gi,
        '$1$2[REDACTED]',
    ],
];

export function redactSecrets(text: string): string {
    for (const [pattern, replacement] of SECRET_PATTERNS) text = text.replace(pattern, replacement);
    return text;
}
const PORT_READ_IDLE_MS = 250;
const PORT_READ_MAX_MS = 5000;
const PORT_READ_MAX_BYTES = 8 * 1024 * 1024;

// The console read port sends the device's buffered output as soon as it receives the
// device's nativeId, then keeps streaming new lines. Collect until the output goes quiet.
function readConsoleViaPort(port: number, host: string, nativeId: string | undefined): Promise<string> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        let idle: NodeJS.Timeout | undefined;
        const socket = net.connect({ port, host });
        const finish = () => {
            clearTimeout(idle);
            clearTimeout(cap);
            socket.destroy();
            resolve(Buffer.concat(chunks).toString());
        };
        const cap = setTimeout(finish, PORT_READ_MAX_MS);
        socket.on('connect', () => {
            // The server reads the first chunk as the filter; "undefined" selects the plugin console.
            socket.write(`${nativeId}\n`);
            idle = setTimeout(finish, PORT_READ_IDLE_MS * 4);
        });
        socket.on('data', (data: Buffer) => {
            chunks.push(data);
            bytes += data.length;
            clearTimeout(idle);
            if (bytes >= PORT_READ_MAX_BYTES) finish();
            else idle = setTimeout(finish, PORT_READ_IDLE_MS);
        });
        socket.on('error', e => {
            clearTimeout(idle);
            clearTimeout(cap);
            reject(e);
        });
    });
}

export async function readConsole(args: z.infer<typeof readConsoleInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    let text: string;
    try {
        text = await plugins.readConsole(args.id);
    } catch {
        const dev = systemManager.getDeviceById(args.id) as { pluginId?: string; nativeId?: string } | undefined;
        if (!dev?.pluginId) throw new Error(`device ${args.id} not found`);
        const [port, host] = await plugins.getRemoteServicePort(dev.pluginId, 'console');
        text = await readConsoleViaPort(port, host || '127.0.0.1', dev.nativeId);
    }
    text = redactSecrets(text.replace(ANSI_ESCAPE, ''));
    const max = args.maxChars ?? 50_000;
    const truncated = text.length > max;
    return { id: args.id, truncated, console: truncated ? text.slice(-max) : text };
}
