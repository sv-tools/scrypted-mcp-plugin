import { connectScryptedClient, type ScryptedClientStatic } from '@scrypted/client';
import { loadConfig } from './config.js';

// One shared connection, lazily established. The MCP server runs over stdio for one client
// (Claude Desktop / Claude Code), so we only ever need a single Scrypted session per process.
let cached: Promise<ScryptedClientStatic> | undefined;

// Drop the cached client so the next getClient() call reconnects. Called from `wrap()` when a
// tool throws a transport error, and from `client.onClose` when the underlying socket closes.
export function invalidateClient() {
    cached = undefined;
}

export async function getClient(): Promise<ScryptedClientStatic> {
    if (!cached) {
        const cfg = loadConfig();
        // Scrypted's default is a self-signed cert. The user runs this MCP locally against
        // their own server, so we accept self-signed by default. Tighten if SCRYPTED_TLS_STRICT=1.
        if (process.env.SCRYPTED_TLS_STRICT !== '1') process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const myPromise: Promise<ScryptedClientStatic> = connectScryptedClient({
            baseUrl: cfg.baseUrl,
            username: cfg.username,
            password: cfg.password,
            pluginId: '@scrypted/core',
        })
            .then(client => {
                // Suspenders: when the underlying engine.io socket closes, drop the cache so
                // the next call rebuilds a fresh client. The retry layer in `wrap()` is the
                // belt — it catches in-flight tool calls that fail before this fires.
                //
                // Scope the invalidation to *this* cached promise: if a reconnect already
                // happened (e.g. via the wrap-retry path) and replaced `cached` with a newer
                // client, a late onClose from this stale client must not clear the fresh one.
                client.onClose = () => {
                    if (cached === myPromise) cached = undefined;
                };
                return client;
            })
            .catch(e => {
                // Reset so a future call retries — useful when the server was just starting.
                if (cached === myPromise) cached = undefined;
                throw e;
            });
        cached = myPromise;
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

// Heuristic: does this error look like a dropped/refused/timed-out connection as opposed to
// a real server-side error? Used by `wrap()` to decide whether to invalidate and retry once.
// Match list is intentionally narrow so a genuine plugin error doesn't get retried twice.
export function isTransientConnectionError(e: any): boolean {
    const msg = String(e?.message ?? e).toLowerCase();
    return /engine\.io|websocket|disconnected|connection (?:closed|reset|refused)|socket hang up|econnrefused|econnreset|etimedout|epipe|eai_again/.test(
        msg,
    );
}
