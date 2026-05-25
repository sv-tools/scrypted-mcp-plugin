import { z } from 'zod';
import { systemManager } from '../scrypted';

export const listDevicesInput = z.object({
    interface: z
        .string()
        .optional()
        .describe(
            'Filter to devices that implement this Scrypted interface (e.g. "OnOff", "VideoCamera", "Brightness").',
        ),
    type: z.string().optional().describe('Filter by ScryptedDeviceType (e.g. "Camera", "Light", "Switch", "Outlet").'),
    name: z.string().optional().describe('Substring match (case-insensitive) on device name.'),
});

export async function listDevices(args: z.infer<typeof listDevicesInput>) {
    const state = systemManager.getSystemState();
    const out: Array<{
        id: string;
        nativeId?: string;
        name: string;
        type: string;
        pluginId?: string;
        room?: string;
        interfaces: string[];
    }> = [];
    const needle = args.name?.toLowerCase();
    for (const id of Object.keys(state)) {
        const dev = state[id];
        const name: string = dev?.name?.value ?? '';
        const type: string = dev?.type?.value ?? '';
        const interfaces: string[] = dev?.interfaces?.value ?? [];
        if (args.interface && !interfaces.includes(args.interface)) continue;
        if (args.type && type !== args.type) continue;
        if (needle && !name.toLowerCase().includes(needle)) continue;
        out.push({
            id,
            nativeId: dev?.nativeId?.value,
            name,
            type,
            pluginId: dev?.pluginId?.value,
            room: dev?.room?.value,
            interfaces,
        });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    return { count: out.length, devices: out };
}

export const getDeviceInput = z.object({
    id: z.string().describe('Scrypted device id (the top-level key from list_devices).'),
});

export async function getDevice(args: z.infer<typeof getDeviceInput>) {
    const state = systemManager.getSystemState();
    const dev = state[args.id];
    if (!dev) throw new Error(`device ${args.id} not found`);
    // Snapshot every property's `value`; skip the noisy timestamp fields the SDK attaches.
    const props: Record<string, any> = {};
    for (const [k, v] of Object.entries(dev as Record<string, any>)) props[k] = v?.value;
    return props;
}

export const callDeviceMethodInput = z.object({
    id: z.string().describe('Scrypted device id (the `id` field from list_devices).'),
    method: z.string().describe('Method name on the device (e.g. "turnOn", "setBrightness", "getSettings").'),
    args: z.array(z.any()).optional().describe('Positional arguments to pass to the method. Omit if none.'),
});

export async function callDeviceMethod(args: z.infer<typeof callDeviceMethodInput>) {
    const dev = systemManager.getDeviceById(args.id) as any;
    if (!dev) throw new Error(`device ${args.id} not found`);
    const fn = dev[args.method];
    if (typeof fn !== 'function') throw new Error(`device ${args.id} does not expose method ${args.method}`);
    const result = await fn.apply(dev, args.args ?? []);
    // RPC results may be remote proxies; stringify defensively so we always return JSON-able data.
    try {
        return { result: JSON.parse(JSON.stringify(result ?? null)) };
    } catch {
        return { result: String(result) };
    }
}
