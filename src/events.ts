import type { ServerNotifier } from '@modelcontextprotocol/server';
import type { EventListenerRegister } from '@scrypted/sdk';
import { systemManager } from './scrypted';

// Per-device resources a client can watch on a `subscriptions/listen` stream
// (resourceSubscriptions). When a device changes we publish
// `notifications/resources/updated` for its URIs and the client re-reads them. The listen
// router matches URIs exactly, so the read side and the notify side must both build URIs
// through these helpers.
export const DEVICE_STATE_URI_TEMPLATE = 'scrypted://device/{id}/state';
export const DEVICE_EVENTS_URI_TEMPLATE = 'scrypted://device/{id}/events';

export function deviceStateUri(id: string): string {
    return `scrypted://device/${id}/state`;
}

export function deviceEventsUri(id: string): string {
    return `scrypted://device/${id}/events`;
}

// Upper bound on concurrently open listen streams, passed to createMcpHandler as
// maxSubscriptions. Each stream is one SSE response, and on Scrypted < 0.148.0 each one
// leaks a cluster connection when it closes (#89), so keep the ceiling low.
export const MAX_LISTEN_STREAMS = 16;

// How many recent events each watched device keeps, and how big one event's data may be once
// serialized. Detections and similar payloads can be large; anything over the cap is
// replaced by a marker rather than truncated mid-JSON.
export const EVENT_LOG_SIZE = 50;
const EVENT_DATA_MAX_CHARS = 4096;

// How often the device list is diffed for adds and removes while any stream is open.
// Scrypted has no single "device added/removed" event we can rely on here, and diffing the
// keys of the in-memory system state is cheap.
const DEVICE_LIST_POLL_MS = 30_000;

export interface DeviceEvent {
    time: number;
    interface?: string;
    property?: string;
    data: unknown;
}

// One open subscriptions/listen stream, as seen from outside the SDK. The SDK owns the wire
// side; we only need to know who opened it, what it watches, and how to close it.
interface ListenStream {
    readonly clientId: string;
    readonly uris: ReadonlySet<string>;
    readonly controller: AbortController;
    expiry?: ReturnType<typeof setTimeout>;
}

export interface ListenHandle {
    // Pass as the Web Request's signal: aborting it makes the SDK tear the stream down.
    signal: AbortSignal;
    // Call once the response is finished (stream ended, client gone, or request rejected).
    // Idempotent.
    done: () => void;
}

type Notifier = Pick<ServerNotifier, 'resourceUpdated' | 'resourcesChanged'>;

function jsonSafe(data: unknown): unknown {
    if (data === undefined) return null;
    try {
        const text = JSON.stringify(data);
        if (text === undefined) return null;
        if (text.length > EVENT_DATA_MAX_CHARS) return { truncated: true, chars: text.length };
        return JSON.parse(text);
    } catch {
        return String(data);
    }
}

// Bridges Scrypted device events onto the MCP handler's change-event bus, and does nothing
// while nobody is listening.
//
// The plugin registers every subscriptions/listen request here before handing it to the
// SDK. The first open stream starts one systemManager.listen() (plus the device-list poll);
// the last one to close stops it. A device's event buffer exists only while some open
// stream watches that device's events URI, so nothing is recorded for devices nobody asked
// about, and the buffer is dropped when the last watcher goes.
//
// Notifications are coalesced per URI: sensors can fire many times a second, so the first
// change opens a short window, later changes ride along, and one notification goes out when
// it closes. A notification only says "re-read this", and every event still lands in the
// buffer, so dropping the intermediate notifications loses nothing.
export class DeviceEventSource {
    private register?: EventListenerRegister;
    private poll?: ReturnType<typeof setInterval>;
    private knownIds = new Set<string>();
    private readonly streams = new Set<ListenStream>();
    // How many open streams watch each URI. Drives which buffers exist and which events
    // are worth publishing at all.
    private readonly watchers = new Map<string, number>();
    private readonly logs = new Map<string, DeviceEvent[]>();
    private readonly pending = new Map<string, ReturnType<typeof setTimeout>>();

    constructor(
        private readonly notify: () => Notifier,
        private readonly console: Console,
        private readonly coalesceMs = 250,
    ) {}

    get openStreams(): number {
        return this.streams.size;
    }

    // Register a listen stream. `expiresAtSec` is the access token's expiry (JWT `exp`); the
    // stream is closed then, since nothing re-checks the token on an open stream.
    open(clientId: string, uris: readonly string[], expiresAtSec?: number): ListenHandle {
        const stream: ListenStream = { clientId, uris: new Set(uris), controller: new AbortController() };
        this.streams.add(stream);
        for (const uri of stream.uris) this.watchers.set(uri, (this.watchers.get(uri) ?? 0) + 1);
        if (expiresAtSec !== undefined) {
            const ms = Math.max(0, expiresAtSec * 1000 - Date.now());
            stream.expiry = setTimeout(() => this.end(stream), ms);
        }
        this.start();
        let finished = false;
        return {
            signal: stream.controller.signal,
            done: () => {
                if (finished) return;
                finished = true;
                this.release(stream);
            },
        };
    }

    // Close open streams: all of them, or those whose client matches. Bookkeeping is released
    // right away rather than when the response finishes, so it can't hinge on Scrypted
    // iterating the stream; the later done() is then a no-op.
    close(match: (clientId: string) => boolean = () => true): number {
        let n = 0;
        for (const stream of [...this.streams]) {
            if (!match(stream.clientId)) continue;
            this.end(stream);
            n++;
        }
        return n;
    }

    private end(stream: ListenStream): void {
        stream.controller.abort();
        this.release(stream);
    }

    // Recent events for one device, oldest first, or undefined when no open stream watches
    // its events URI (so nothing is being recorded).
    recentEvents(id: string): DeviceEvent[] | undefined {
        const log = this.logs.get(id);
        return log ? [...log] : undefined;
    }

    private release(stream: ListenStream): void {
        if (!this.streams.delete(stream)) return;
        if (stream.expiry) clearTimeout(stream.expiry);
        for (const uri of stream.uris) {
            const n = (this.watchers.get(uri) ?? 1) - 1;
            if (n > 0) {
                this.watchers.set(uri, n);
                continue;
            }
            this.watchers.delete(uri);
            const timer = this.pending.get(uri);
            if (timer) clearTimeout(timer);
            this.pending.delete(uri);
        }
        for (const id of this.logs.keys()) if (!this.watchers.has(deviceEventsUri(id))) this.logs.delete(id);
        if (this.streams.size === 0) this.stop();
    }

    private start(): void {
        if (this.register) return;
        this.knownIds = this.currentIds();
        this.register = systemManager.listen((source, details, data) => {
            const id = source?.id;
            if (id) this.onEvent(id, details, data);
        });
        this.poll = setInterval(() => this.checkDeviceList(), DEVICE_LIST_POLL_MS);
    }

    private stop(): void {
        this.register?.removeListener();
        this.register = undefined;
        if (this.poll) clearInterval(this.poll);
        this.poll = undefined;
        for (const timer of this.pending.values()) clearTimeout(timer);
        this.pending.clear();
        this.watchers.clear();
        this.logs.clear();
    }

    private onEvent(
        id: string,
        details: { eventTime?: number; eventInterface?: string; property?: string },
        data: unknown,
    ) {
        const eventsUri = deviceEventsUri(id);
        if (this.watchers.has(eventsUri)) {
            let log = this.logs.get(id);
            if (!log) {
                log = [];
                this.logs.set(id, log);
            }
            log.push({
                time: details?.eventTime ?? Date.now(),
                interface: details?.eventInterface,
                property: details?.property,
                data: jsonSafe(data),
            });
            if (log.length > EVENT_LOG_SIZE) log.splice(0, log.length - EVENT_LOG_SIZE);
            this.schedule(eventsUri);
        }
        // Only property changes alter what the state resource returns.
        const stateUri = deviceStateUri(id);
        if (details?.property && this.watchers.has(stateUri)) this.schedule(stateUri);
    }

    private currentIds(): Set<string> {
        return new Set(Object.keys(systemManager.getSystemState()));
    }

    private checkDeviceList(): void {
        const ids = this.currentIds();
        const changed = ids.size !== this.knownIds.size || [...ids].some(id => !this.knownIds.has(id));
        if (!changed) return;
        this.knownIds = ids;
        this.publish(n => n.resourcesChanged());
    }

    private schedule(uri: string): void {
        if (this.pending.has(uri)) return;
        const timer = setTimeout(() => {
            this.pending.delete(uri);
            this.publish(n => n.resourceUpdated(uri));
        }, this.coalesceMs);
        this.pending.set(uri, timer);
    }

    private publish(send: (n: Notifier) => void): void {
        try {
            send(this.notify());
        } catch (e) {
            this.console.error('[scrypted-mcp] change-event publish failed:', e);
        }
    }
}
