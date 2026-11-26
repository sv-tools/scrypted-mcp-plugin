import Module from 'node:module';
import path from 'node:path';

export class MemoryStorage {
    private readonly map = new Map<string, string>();

    get length(): number {
        return this.map.size;
    }

    key(index: number): string | null {
        return [...this.map.keys()][index] ?? null;
    }

    getItem(key: string): string | null {
        return this.map.get(key) ?? null;
    }

    setItem(key: string, value: string): void {
        this.map.set(key, String(value));
    }

    removeItem(key: string): void {
        this.map.delete(key);
    }

    clear(): void {
        this.map.clear();
    }

    keys(): string[] {
        return [...this.map.keys()];
    }
}

export const nullConsole = {
    log: () => {},
    error: () => {},
    warn: () => {},
    info: () => {},
    debug: () => {},
} as unknown as Console;

export type ListenCallback = (
    source: { id?: string } | undefined,
    details: { eventTime?: number; eventInterface?: string; property?: string },
    data: unknown,
) => void;

export interface MockSdkState {
    systemState: Record<string, any>;
    devices: Record<string, any>;
    components: Record<string, any>;
    listeners: Set<ListenCallback>;
    convertMediaObjectToBuffer: (mo: any, toMimeType: string) => Promise<Buffer | Uint8Array>;
}

export const mockState: MockSdkState = {
    systemState: {},
    devices: {},
    components: {},
    listeners: new Set(),
    convertMediaObjectToBuffer: async () => Buffer.alloc(0),
};

export function resetMockSdk(): void {
    mockState.systemState = {};
    mockState.devices = {};
    mockState.components = {};
    mockState.listeners.clear();
    mockState.convertMediaObjectToBuffer = async () => Buffer.alloc(0);
}

export const mockSdk = {
    systemManager: {
        getSystemState: () => mockState.systemState,
        getDeviceById: (id: string) => mockState.devices[id],
        getComponent: async (name: string) => {
            if (!(name in mockState.components)) throw new Error(`component ${name} not found`);
            return mockState.components[name];
        },
        listen: (cb: ListenCallback) => {
            mockState.listeners.add(cb);
            return {
                removeListener: () => {
                    mockState.listeners.delete(cb);
                },
            };
        },
    },
    deviceManager: {},
    mediaManager: {
        convertMediaObjectToBuffer: (mo: any, toMimeType: string) =>
            mockState.convertMediaObjectToBuffer(mo, toMimeType),
    },
    endpointManager: {},
};

let installed = false;

export function installScryptedSdkMock(): void {
    if (installed) return;
    installed = true;
    const typesPath = path.join(process.cwd(), 'node_modules', '@scrypted', 'sdk', 'dist', 'types', 'gen', 'index.js');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const types = require(typesPath);
    const mod = { ...types, sdk: mockSdk, default: mockSdk };
    const origLoad = (Module as any)._load;
    (Module as any)._load = function (request: string, parent: unknown, isMain: boolean) {
        if (request === '@scrypted/sdk') return mod;
        return origLoad.call(this, request, parent, isMain);
    };
}
