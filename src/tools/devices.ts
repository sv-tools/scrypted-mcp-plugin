import {
    ScryptedInterface,
    ScryptedMimeTypes,
    type Camera,
    type MediaObject,
    type RequestPictureOptions,
} from '@scrypted/sdk';
import { z } from 'zod';
import { mediaManager, systemManager } from '../scrypted';

// Upper bound on inline base64 image payloads returned over MCP. Typical camera JPEGs are
// 100KB-2MB; 10MB gives headroom for high-res stills without risking OOM or overflowing
// client context limits.
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

// Image MIME types that MCP clients (Claude, etc.) consume directly without transcoding.
// Requesting the same MIME type from Scrypted's mediaManager unwraps the buffer directly
// without needing a transcoder plugin.
const DIRECT_IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

function textContent(payload: unknown) {
    return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

function normalizeMimeType(mimeType: string): string {
    return mimeType.split(';')[0].trim().toLowerCase();
}

function isMediaObject(val: unknown): val is MediaObject {
    if (!val || typeof val !== 'object' || Array.isArray(val) || ArrayBuffer.isView(val)) return false;
    const obj = val as Record<string, unknown>;
    if (typeof obj.mimeType !== 'string' || obj.mimeType.length === 0) return false;
    // Scrypted MediaObjects crossing RPC are Proxy objects whose target has no own enumerable
    // keys (which is why JSON.stringify turns them into "{}"), or carry the internal proxy
    // marker / a convert() method. Require one of these so plain JSON objects that merely
    // contain a `mimeType` field are serialized normally.
    return (
        Boolean(obj.__rpcproxy_traps_all_properties) ||
        Object.keys(obj).length === 0 ||
        typeof obj.convert === 'function'
    );
}

function isImageMimeType(mimeType: string): boolean {
    const normalized = normalizeMimeType(mimeType);
    return normalized.startsWith('image/') || normalized === ScryptedMimeTypes.Image;
}

async function mediaObjectToImageBuffer(mo: MediaObject): Promise<{ buf: Buffer; mimeType: string }> {
    const normalized = typeof mo.mimeType === 'string' ? normalizeMimeType(mo.mimeType) : '';
    const targetMime = DIRECT_IMAGE_MIMES.has(normalized) ? normalized : 'image/jpeg';
    const raw = await mediaManager.convertMediaObjectToBuffer(mo, targetMime);
    if (!raw) throw new Error('media conversion returned an empty image');
    // RPC peer may return a Uint8Array rather than a real Node Buffer.
    const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as unknown as ArrayBufferLike);
    if (buf.length === 0) throw new Error('media conversion returned an empty image');
    if (buf.length > MAX_IMAGE_BYTES) {
        throw new Error(
            `image is ${buf.length} bytes, which exceeds the ${MAX_IMAGE_BYTES}-byte limit; request a smaller width/height`,
        );
    }
    return { buf, mimeType: targetMime };
}

function describeMediaObject(mo: MediaObject): Record<string, unknown> {
    // Accessing an absent property on a Scrypted RpcProxy returns a function stub rather than
    // undefined, so type-check optional fields before copying them.
    const info: Record<string, unknown> = {
        mediaObject: true,
        mimeType: mo.mimeType,
    };
    if (typeof mo.sourceId === 'string') info.sourceId = mo.sourceId;
    if (Array.isArray(mo.toMimeTypes)) info.toMimeTypes = mo.toMimeTypes;
    return info;
}

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

export const getSnapshotInput = z.object({
    id: z.string().describe('Scrypted device id of a Camera device (the `id` field from list_devices).'),
    width: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(
            'Optional requested snapshot width in pixels (honored if the camera or snapshot plugin supports resizing).',
        ),
    height: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(
            'Optional requested snapshot height in pixels (honored if the camera or snapshot plugin supports resizing).',
        ),
    timeout: z
        .number()
        .int()
        .positive()
        .max(60_000)
        .optional()
        .describe('Optional maximum time in milliseconds to wait for the snapshot (max 60000).'),
});

export async function getSnapshot(args: z.infer<typeof getSnapshotInput>) {
    const state = systemManager.getSystemState()[args.id];
    if (!state) throw new Error(`device ${args.id} not found`);
    const interfaces: string[] = state?.interfaces?.value ?? [];
    if (!interfaces.includes(ScryptedInterface.Camera)) {
        throw new Error(`device ${args.id} does not implement ${ScryptedInterface.Camera}`);
    }
    const dev = systemManager.getDeviceById<Camera>(args.id);
    if (!dev || typeof dev.takePicture !== 'function') {
        throw new Error(`device ${args.id} does not expose takePicture`);
    }

    const options: RequestPictureOptions = {};
    if (args.width !== undefined || args.height !== undefined) {
        options.picture = {};
        if (args.width !== undefined) options.picture.width = args.width;
        if (args.height !== undefined) options.picture.height = args.height;
    }
    if (args.timeout !== undefined) options.timeout = args.timeout;

    const mo = await dev.takePicture(Object.keys(options).length > 0 ? options : undefined);
    if (!mo) throw new Error(`camera ${args.id} returned no snapshot`);

    const { buf, mimeType } = await mediaObjectToImageBuffer(mo);
    const summary: Record<string, unknown> = {
        id: args.id,
        name: state?.name?.value ?? '',
        mimeType,
        bytes: buf.length,
    };
    return {
        content: [
            { type: 'text' as const, text: JSON.stringify(summary, null, 2) },
            { type: 'image' as const, data: buf.toString('base64'), mimeType },
        ],
    };
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

    if (isMediaObject(result)) {
        if (isImageMimeType(result.mimeType)) {
            const { buf, mimeType } = await mediaObjectToImageBuffer(result);
            const summary: Record<string, unknown> = { mimeType, bytes: buf.length };
            if (typeof result.sourceId === 'string') summary.sourceId = result.sourceId;
            return {
                content: [
                    { type: 'text' as const, text: JSON.stringify(summary, null, 2) },
                    { type: 'image' as const, data: buf.toString('base64'), mimeType },
                ],
            };
        }
        return textContent({ result: describeMediaObject(result) });
    }

    // RPC results may be remote proxies; stringify defensively so we always return JSON-able data.
    try {
        return textContent({ result: JSON.parse(JSON.stringify(result ?? null)) });
    } catch {
        return textContent({ result: String(result) });
    }
}
