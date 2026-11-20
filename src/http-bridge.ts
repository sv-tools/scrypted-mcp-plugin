import type { HttpRequest, HttpResponse } from '@scrypted/sdk';

// Synthetic origin used when building Web standard Request objects from Scrypted's
// HttpRequest. Scrypted's `url` is path-relative (e.g. "/endpoint/scrypted-mcp/mcp?…"); the
// MCP transport only inspects pathname/searchParams, so the host part doesn't matter as long
// as `new URL(...)` can parse the result.
const SYNTHETIC_ORIGIN = 'http://scrypted-mcp.local';

// `signal` lets the caller end a long-lived exchange from our side: the SDK tears a
// subscriptions/listen stream down when its request's signal aborts.
export function toWebRequest(req: HttpRequest, signal?: AbortSignal): Request {
    const method = (req.method ?? 'GET').toUpperCase();
    const url = new URL(req.url ?? '/', SYNTHETIC_ORIGIN).toString();

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers ?? {})) {
        if (typeof v === 'string') headers.set(k, v);
    }

    // GET/HEAD bodies are forbidden by the Web Fetch spec. Scrypted's bodyParser.text()
    // middleware leaves `body` empty for those methods anyway, so this is just defensive.
    const init: RequestInit = { method, headers, signal };
    if (method !== 'GET' && method !== 'HEAD' && req.body !== undefined) init.body = req.body;
    return new Request(url, init);
}

// Drain a Web ReadableStream<Uint8Array> as an AsyncGenerator<Buffer> for Scrypted's
// sendStream(...). The MCP transport's SSE response keeps the stream open until the
// per-request work finishes; on each yield Scrypted forwards the chunk to the client.
//
// When the client disconnects, Scrypted stops iterating and calls return() on this
// generator (via RPC). We must cancel the reader in that case, not just release the lock:
// cancel() is what fires the transport's ReadableStream `cancel` callback, which drops the
// stream from its mapping and clears its keep-alive timer. Without it the abandoned stream
// lingers with its keep-alive timer running until the per-request server is closed.
//
// `opts.signal` ends the stream from our side: on abort we cancel the reader, which runs the
// source's cancel callback (the SDK's teardown) and ends the generator, so Scrypted closes the
// response. The Request's own signal isn't enough: Node's Request follows the caller's signal
// through a derived one, and that link didn't fire for an open listen stream in testing.
async function* readableStreamToBufferGenerator(
    stream: ReadableStream<Uint8Array>,
    opts: StreamResponseOptions = {},
): AsyncGenerator<Buffer, void> {
    const reader = stream.getReader();
    let finished = false;
    const onAbort = () => {
        reader.cancel().catch(() => {});
    };
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    if (opts.signal?.aborted) onAbort();
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                finished = true;
                return;
            }
            if (value && value.byteLength > 0) yield Buffer.from(value.buffer, value.byteOffset, value.byteLength);
        }
    } finally {
        if (!finished) {
            // Fire-and-forget: cancel() resolves once the source's cancel callback runs,
            // and we don't want a slow/throwing callback to block generator teardown.
            reader.cancel().catch(() => {});
        }
        try {
            reader.releaseLock();
        } catch {
            // Best-effort: a cancelled stream may already be locked-released.
        }
        opts.signal?.removeEventListener('abort', onAbort);
        opts.onDone?.();
    }
}

function headersToPlain(headers: Headers): Record<string, string> {
    const out: Record<string, string> = {};
    headers.forEach((value, key) => {
        out[key] = value;
    });
    return out;
}

// Forward a Web standard Response to a Scrypted HttpResponse. Streamed bodies (SSE) keep the
// HTTP response open and pump chunks; non-streamed responses buffer the whole body once and
// send it as a single send() call. We pick branches off Content-Type rather than off whether
// `body` is non-null — every Response has a ReadableStream, including 1-byte JSON ones, so
// "is it streaming?" really means "did we negotiate text/event-stream?".
//
export interface StreamResponseOptions {
    // Runs once the response is over: for a stream, when it ends or the client goes away
    // (sendStream isn't awaited, so returning from fromWebResponse says nothing about that);
    // otherwise right after the send.
    onDone?: () => void;
    // Aborting it ends a streamed response from our side.
    signal?: AbortSignal;
}

export async function fromWebResponse(
    response: Response,
    httpResponse: HttpResponse,
    opts: StreamResponseOptions = {},
): Promise<void> {
    const code = response.status;
    const headers = headersToPlain(response.headers);
    const contentType = response.headers.get('content-type') ?? '';
    const isSse = contentType.toLowerCase().includes('text/event-stream');

    if (isSse && response.body) {
        httpResponse.sendStream(readableStreamToBufferGenerator(response.body, opts), { code, headers });
        return;
    }

    try {
        if (response.body) {
            const buf = Buffer.from(await response.arrayBuffer());
            httpResponse.send(buf, { code, headers });
            return;
        }
        httpResponse.send('', { code, headers });
    } finally {
        opts.onDone?.();
    }
}

// Convenience for our own OAuth handlers — they build a Response, this hands it to Scrypted.
// Same shape as fromWebResponse, but accepting the raw pieces so callers don't have to
// construct a Response just to immediately tear it back down.
export function sendJson(
    httpResponse: HttpResponse,
    code: number,
    body: unknown,
    extraHeaders?: Record<string, string>,
) {
    httpResponse.send(JSON.stringify(body), {
        code,
        headers: { 'Content-Type': 'application/json', ...(extraHeaders ?? {}) },
    });
}

export function sendText(
    httpResponse: HttpResponse,
    code: number,
    body: string,
    extraHeaders?: Record<string, string>,
) {
    httpResponse.send(body, {
        code,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', ...(extraHeaders ?? {}) },
    });
}

export function sendHtml(
    httpResponse: HttpResponse,
    code: number,
    body: string,
    extraHeaders?: Record<string, string>,
) {
    httpResponse.send(body, {
        code,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...(extraHeaders ?? {}) },
    });
}

export function sendRedirect(httpResponse: HttpResponse, location: string) {
    httpResponse.send('', { code: 302, headers: { Location: location } });
}
