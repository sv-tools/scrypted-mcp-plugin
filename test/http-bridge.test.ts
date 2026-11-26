import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { HttpResponse } from '@scrypted/sdk';
import { fromWebResponse, toWebRequest } from '../src/http-bridge';

describe('http-bridge', () => {
    it('converts HttpRequest to Web Request without body on GET', async () => {
        const getReq = toWebRequest({
            url: '/endpoint/scrypted-mcp/public/mcp?x=1',
            method: 'GET',
            headers: { accept: 'application/json' },
            body: 'ignored',
        });
        assert.equal(getReq.method, 'GET');
        assert.equal(new URL(getReq.url).pathname, '/endpoint/scrypted-mcp/public/mcp');
        assert.equal(getReq.body, null);

        const postReq = toWebRequest({
            url: '/endpoint/scrypted-mcp/public/mcp',
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{"ok":true}',
        });
        assert.equal(await postReq.text(), '{"ok":true}');
    });

    it('buffers non-SSE responses and calls onDone', async () => {
        let sentBody: unknown;
        let sentOpts: unknown;
        let doneCalls = 0;
        const res = {
            send(body: unknown, opts?: unknown) {
                sentBody = body;
                sentOpts = opts;
            },
        } as unknown as HttpResponse;

        await fromWebResponse(
            new Response(JSON.stringify({ hello: 'world' }), {
                status: 201,
                headers: { 'content-type': 'application/json', 'x-custom': 'yes' },
            }),
            res,
            {
                onDone: () => {
                    doneCalls++;
                },
            },
        );
        assert.equal(Buffer.isBuffer(sentBody), true);
        assert.deepEqual(JSON.parse((sentBody as Buffer).toString('utf8')), { hello: 'world' });
        assert.deepEqual(sentOpts, {
            code: 201,
            headers: { 'content-type': 'application/json', 'x-custom': 'yes' },
        });
        assert.equal(doneCalls, 1);
    });

    it('streams SSE responses, cancels reader on abort, and calls onDone', async () => {
        let cancelled = false;
        let doneCalls = 0;
        let generator: AsyncGenerator<Buffer, void> | undefined;

        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new TextEncoder().encode('data: first\n\n'));
            },
            cancel() {
                cancelled = true;
            },
        });
        const res = {
            sendStream(gen: AsyncGenerator<Buffer, void>) {
                generator = gen;
            },
        } as unknown as HttpResponse;

        const ac = new AbortController();
        await fromWebResponse(
            new Response(stream, {
                status: 200,
                headers: { 'content-type': 'text/event-stream', 'x-accel-buffering': 'no' },
            }),
            res,
            {
                signal: ac.signal,
                onDone: () => {
                    doneCalls++;
                },
            },
        );

        assert.ok(generator);
        const first = await generator.next();
        assert.equal(first.done, false);
        assert.equal(first.value?.toString('utf8'), 'data: first\n\n');

        const nextPromise = generator.next();
        ac.abort();
        const afterAbort = await nextPromise;
        assert.equal(afterAbort.done, true);
        assert.equal(cancelled, true);
        assert.equal(doneCalls, 1);
    });
});
