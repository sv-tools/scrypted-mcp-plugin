import { z } from 'zod';
import { getClient, getComponent } from '../scrypted.js';

interface PluginComponent {
    getPluginInfo(pluginId: string): Promise<any>;
    reload(pluginId: string): Promise<void>;
    kill(pluginId: string): Promise<void>;
    installNpm(pkg: string, version?: string): Promise<string>;
    updatePlugins(): Promise<any>;
}

export const listPluginsInput = z.object({});

export async function listPlugins() {
    const client = await getClient();
    const state = client.systemManager.getSystemState();
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
    pluginId: z.string().describe('npm package id of the plugin, e.g. "@scrypted/kasa".'),
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
    npmPackage: z.string().describe('npm package id, e.g. "@scrypted/kasa".'),
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
