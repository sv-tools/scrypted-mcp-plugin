import { z } from 'zod';
import { getComponent, systemManager } from '../scrypted';

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
    pluginId: z.string().describe('npm package id of the plugin, e.g. "scrypted-kasa".'),
});

export async function getPluginInfo(args: z.infer<typeof getPluginInfoInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    const info = await plugins.getPluginInfo(args.pluginId);
    return info ?? { error: 'plugin not found' };
}

export const reloadPluginInput = z.object({
    pluginId: z.string().describe('npm package id of the plugin to reload.'),
});

export async function reloadPlugin(args: z.infer<typeof reloadPluginInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.reload(args.pluginId);
    return { reloaded: args.pluginId };
}

export const killPluginInput = z.object({
    pluginId: z.string().describe('npm package id of the plugin to kill (without reload).'),
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
    return plugins.updatePlugins();
}

export const renameDeviceIdInput = z.object({
    id: z.string().describe('Current Scrypted device id.'),
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
    id: z.string().describe('Scrypted device id whose mixins to replace.'),
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
    id: z.string().describe('Scrypted device id whose persistent storage to read.'),
});

export async function getStorage(args: z.infer<typeof getStorageInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    const storage = await plugins.getStorage(args.id);
    return { id: args.id, storage: storage ?? {} };
}

export const setStorageInput = z.object({
    id: z.string().describe('Scrypted device id whose persistent storage to overwrite.'),
    storage: z
        .record(z.string(), z.string())
        .describe(
            "Replacement storage map (keys and values are strings). REPLACES the device's entire storage — read get_storage first if you only want to change one key.",
        ),
});

export async function setStorage(args: z.infer<typeof setStorageInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.setStorage(args.id, args.storage);
    return { id: args.id, storage: args.storage };
}

export const getIdForNativeIdInput = z.object({
    pluginId: z.string().describe('npm package id of the owning plugin (e.g. "scrypted-kasa").'),
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
    pluginId: z.string().describe('npm package id of the plugin whose websocket clients to disconnect.'),
});

export async function disconnectClients(args: z.infer<typeof disconnectClientsInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.disconnectClients(args.pluginId);
    return { disconnected: args.pluginId };
}

export const clearConsoleInput = z.object({
    id: z.string().describe('Scrypted device id whose console buffer to clear.'),
});

export async function clearConsole(args: z.infer<typeof clearConsoleInput>) {
    const plugins = await getComponent<PluginComponent>('plugins');
    await plugins.clearConsole(args.id);
    return { cleared: args.id };
}
