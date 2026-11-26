import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { installScryptedSdkMock, mockState, nullConsole, resetMockSdk } from './helpers/mock-scrypted';

installScryptedSdkMock();

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { DeviceEventSource, EVENT_LOG_SIZE, deviceEventsUri, deviceStateUri } = require('../src/events');

describe('DeviceEventSource', () => {
    beforeEach(() => {
        resetMockSdk();
    });

    it('reports recording immediately on open before any event arrives, buffers events, and cleans up on close', async () => {
        const updated: string[] = [];
        const notifier = {
            resourceUpdated: (uri: string) => updated.push(uri),
            resourcesChanged: () => {},
        };
        const source = new DeviceEventSource(() => notifier, nullConsole, 10);

        assert.equal(source.recentEvents('42'), undefined);
        assert.equal(mockState.listeners.size, 0);

        const handle = source.open('client-1', [deviceEventsUri('42'), deviceStateUri('42')]);
        assert.equal(mockState.listeners.size, 1);
        // Regression: subscribing starts recording immediately, even before the first event fires.
        assert.deepEqual(source.recentEvents('42'), []);
        assert.equal(source.recentEvents('99'), undefined);

        const [listener] = [...mockState.listeners];
        listener({ id: '42' }, { eventTime: 1000, eventInterface: 'MotionSensor', property: 'motionDetected' }, true);
        listener({ id: '42' }, { eventTime: 1001, eventInterface: 'MotionSensor' }, { score: 0.9 });

        const recent = source.recentEvents('42');
        assert.equal(recent?.length, 2);
        assert.equal(recent?.[0].data, true);
        assert.deepEqual(recent?.[1].data, { score: 0.9 });

        // Wait for coalesced notification
        await new Promise(r => setTimeout(r, 30));
        assert.deepEqual(updated.sort(), [deviceEventsUri('42'), deviceStateUri('42')].sort());

        // Cap buffer at EVENT_LOG_SIZE
        for (let i = 0; i < EVENT_LOG_SIZE + 5; i++) {
            listener({ id: '42' }, { eventTime: 2000 + i, eventInterface: 'Test' }, i);
        }
        assert.equal(source.recentEvents('42')?.length, EVENT_LOG_SIZE);

        // Close releases listener and drops buffer
        handle.done();
        assert.equal(mockState.listeners.size, 0);
        assert.equal(source.recentEvents('42'), undefined);
    });

    it('closes matching client streams via close()', () => {
        const notifier = { resourceUpdated: () => {}, resourcesChanged: () => {} };
        const source = new DeviceEventSource(() => notifier, nullConsole, 10);

        const h1 = source.open('api-token:aaa', [deviceEventsUri('1')]);
        const h2 = source.open('api-token:bbb', [deviceEventsUri('2')]);

        assert.equal(
            source.close((id: string) => id === 'api-token:aaa'),
            1,
        );
        assert.equal(h1.signal.aborted, true);
        assert.equal(h2.signal.aborted, false);
        assert.equal(source.recentEvents('1'), undefined);
        assert.deepEqual(source.recentEvents('2'), []);

        h2.done();
        assert.equal(mockState.listeners.size, 0);
    });
});
