import { connectScryptedClient, type ScryptedClientStatic } from '@scrypted/client';
import { loadConfig } from './config.js';

// One shared connection, lazily established. The MCP server runs over stdio for one client
// (Claude Desktop / Claude Code), so we only ever need a single Scrypted session per process.
let cached: Promise<ScryptedClientStatic> | undefined;

export async function getClient(): Promise<ScryptedClientStatic> {
    if (!cached) {
        const cfg = loadConfig();
        // Scrypted's default is a self-signed cert. The user runs this MCP locally against
        // their own server, so we accept self-signed by default. Tighten if SCRYPTED_TLS_STRICT=1.
        if (process.env.SCRYPTED_TLS_STRICT !== '1') process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        cached = connectScryptedClient({
            baseUrl: cfg.baseUrl,
            username: cfg.username,
            password: cfg.password,
            pluginId: '@scrypted/core',
        }).catch(e => {
            // Reset so a future call retries — useful when the server was just starting.
            cached = undefined;
            throw e;
        });
    }
    return cached;
}

// Component lookups via the RPC peer. Components are runtime-registered services on the
// Scrypted server (logger, plugins, alerts, …) — typed loosely because @scrypted/types
// doesn't ship narrow types for each one.
export async function getComponent<T = any>(name: string): Promise<T> {
    const client = await getClient();
    return client.systemManager.getComponent(name) as Promise<T>;
}
