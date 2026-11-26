import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { installScryptedSdkMock, mockState, resetMockSdk } from './helpers/mock-scrypted';

installScryptedSdkMock();

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { callDeviceMethod, getSnapshot } = require('../src/tools/devices');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getStorage, listPlugins, setStorage } = require('../src/tools/plugins');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getLogs } = require('../src/tools/logs');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { listAlerts } = require('../src/tools/alerts');

function makeMediaObjectProxy(props: { mimeType: string; sourceId?: string; toMimeTypes?: string[] }) {
    return new Proxy(
        {},
        {
            get(_target, prop) {
                // Real Scrypted RpcProxy returns undefined for `then` so `await` doesn't treat
                // the proxy as a Promise/thenable.
                if (prop === 'then') return undefined;
                if (prop === '__rpcproxy_traps_all_properties') return true;
                if (prop in props) return (props as Record<PropertyKey, unknown>)[prop];
                // Scrypted RpcProxy returns a method stub for unknown properties.
                return () => {};
            },
        },
    );
}

describe('device, plugin, log, and alert tools', () => {
    beforeEach(() => {
        resetMockSdk();
    });

    it('listPlugins returns only plugin root devices (no nativeId)', async () => {
        mockState.systemState = {
            '1': {
                pluginId: { value: '@scrypted/ring' },
                name: { value: 'Ring Plugin' },
                type: { value: 'API' },
            },
            '2': {
                pluginId: { value: '@scrypted/ring' },
                nativeId: { value: 'cam-front' },
                name: { value: 'Front Door' },
                type: { value: 'Camera' },
            },
            '3': {
                pluginId: { value: 'scrypted-mcp' },
                name: { value: 'MCP Server' },
                type: { value: 'API' },
            },
        };

        const res = await listPlugins();
        assert.equal(res.count, 2);
        assert.deepEqual(
            res.plugins.map((p: any) => p.id),
            ['3', '1'],
        );
    });

    it('getSnapshot validates Camera interface, passes options, and returns MCP image content', async () => {
        mockState.systemState = {
            '10': { name: { value: 'Porch' }, interfaces: { value: ['Camera', 'VideoCamera'] } },
            '11': { name: { value: 'Lamp' }, interfaces: { value: ['OnOff'] } },
        };

        let seenOptions: unknown;
        let seenTargetMime: string | undefined;
        const fakePng = Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
        mockState.devices['10'] = {
            takePicture: async (opts: unknown) => {
                seenOptions = opts;
                return makeMediaObjectProxy({ mimeType: 'image/png', sourceId: '10' });
            },
        };
        mockState.convertMediaObjectToBuffer = async (_mo, toMime) => {
            seenTargetMime = toMime;
            return new Uint8Array(fakePng);
        };

        await assert.rejects(() => getSnapshot({ id: '99' }), /not found/);
        await assert.rejects(() => getSnapshot({ id: '11' }), /does not implement Camera/);

        const out = await getSnapshot({ id: '10', width: 640, height: 360, timeout: 5000 });
        assert.deepEqual(seenOptions, { picture: { width: 640, height: 360 }, timeout: 5000 });
        assert.equal(seenTargetMime, 'image/png');
        assert.equal(out.content.length, 2);
        assert.deepEqual(JSON.parse(out.content[0].text), {
            id: '10',
            name: 'Porch',
            mimeType: 'image/png',
            bytes: fakePng.length,
        });
        assert.deepEqual(out.content[1], {
            type: 'image',
            data: fakePng.toString('base64'),
            mimeType: 'image/png',
        });
    });

    it('callDeviceMethod handles image MediaObjects, non-image MediaObjects, and plain objects with mimeType', async () => {
        const fakeJpeg = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
        mockState.convertMediaObjectToBuffer = async () => fakeJpeg;
        mockState.devices['30'] = {
            takePicture: async () => makeMediaObjectProxy({ mimeType: 'x-scrypted/x-scrypted-image', sourceId: '30' }),
            getVideoStream: async () =>
                makeMediaObjectProxy({
                    mimeType: 'x-scrypted/x-ffmpeg-input',
                    sourceId: '30',
                    toMimeTypes: ['video/mp4'],
                }),
            getPlainMetadata: async () => ({ mimeType: 'image/jpeg', url: 'https://example.com/a.jpg' }),
        };

        const imgRes = await callDeviceMethod({ id: '30', method: 'takePicture' });
        assert.equal(imgRes.content.length, 2);
        assert.equal(imgRes.content[1].type, 'image');
        assert.equal(imgRes.content[1].mimeType, 'image/jpeg');
        assert.equal(imgRes.content[1].data, fakeJpeg.toString('base64'));

        const vidRes = await callDeviceMethod({ id: '30', method: 'getVideoStream' });
        assert.equal(vidRes.content.length, 1);
        assert.deepEqual(JSON.parse(vidRes.content[0].text), {
            result: {
                mediaObject: true,
                mimeType: 'x-scrypted/x-ffmpeg-input',
                sourceId: '30',
                toMimeTypes: ['video/mp4'],
            },
        });

        const plainRes = await callDeviceMethod({ id: '30', method: 'getPlainMetadata' });
        assert.equal(plainRes.content.length, 1);
        assert.deepEqual(JSON.parse(plainRes.content[0].text), {
            result: { mimeType: 'image/jpeg', url: 'https://example.com/a.jpg' },
        });
    });

    it('getLogs and listAlerts redact credentials in messages', async () => {
        mockState.components.logger = {
            getLogs: async () => [
                {
                    timestamp: 1700000000000,
                    level: 'e',
                    title: '/plugins/cam',
                    message: 'failed rtsp://admin:hunter2@10.0.0.5:554/stream Authorization: Bearer tok_123',
                },
            ],
        };
        mockState.components.alerts = {
            getAlerts: async () => [
                {
                    _id: 'a1',
                    timestamp: 1700000000000,
                    title: 'Camera',
                    path: '/device/1',
                    message: '{"Authorization": "Basic c2VjcmV0"}',
                },
            ],
        };

        const logs = await getLogs({});
        assert.ok(!logs.entries[0].message.includes('hunter2'));
        assert.ok(!logs.entries[0].message.includes('tok_123'));

        const alerts = await listAlerts({});
        assert.ok(!alerts.alerts[0].message.includes('c2VjcmV0'));
        assert.equal(alerts.alerts[0].message, '{"Authorization": "[REDACTED]"}');
    });

    it('refuses get_storage and set_storage on scrypted-mcp itself', async () => {
        mockState.devices['99'] = { pluginId: 'scrypted-mcp' };
        await assert.rejects(() => getStorage({ id: '99' }), /refusing to read\/write/);
        await assert.rejects(() => setStorage({ id: '99', storage: {} }), /refusing to read\/write/);
    });
});
