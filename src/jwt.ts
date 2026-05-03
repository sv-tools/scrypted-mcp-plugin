import { webcrypto } from 'node:crypto';

// Tiny JWT implementation focused on the single algorithm we use (ES256, ECDSA over P-256
// with SHA-256). We keep this in-house instead of pulling in `jose` because it's the only
// crypto we need and we want to stay on plain CommonJS — `jose` is ESM-only and dragging
// `"type": "module"` through the scrypted-webpack toolchain causes more pain than it's
// worth for ~50 lines of code.

const ALG = 'ES256';
const NAMED_CURVE = 'P-256';

const subtle = webcrypto.subtle;

export interface JWK {
    kty: string;
    crv?: string;
    x?: string;
    y?: string;
    d?: string;
    alg?: string;
    use?: string;
    kid?: string;
}

export interface SigningKey {
    privateJwk: JWK;
    publicJwk: JWK;
    privateKey: webcrypto.CryptoKey;
    publicKey: webcrypto.CryptoKey;
    kid: string;
}

function base64urlEncode(buf: Buffer | Uint8Array): string {
    return Buffer.from(buf).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// `BufferSource` (the WebCrypto input type) requires Uint8Array<ArrayBuffer>, not the
// `Uint8Array<ArrayBufferLike>` returned by `Uint8Array.from(Buffer)` or `TextEncoder.encode`.
// Newer @types/node tightened the generic; older WebCrypto sig still expects ArrayBuffer.
// `toArrayBuffer` rebuilds a Uint8Array over a fresh ArrayBuffer to satisfy the strict type.
function toArrayBuffer(view: ArrayBufferView): Uint8Array<ArrayBuffer> {
    const ab = new ArrayBuffer(view.byteLength);
    new Uint8Array(ab).set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    return new Uint8Array(ab);
}

function base64urlDecode(s: string): Uint8Array<ArrayBuffer> {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    return toArrayBuffer(Buffer.from(s, 'base64'));
}

const utf8 = new TextEncoder();

function ascii(s: string): Uint8Array<ArrayBuffer> {
    // ASCII is a subset of UTF-8, and our inputs (base64url segments and JSON) are ASCII-only.
    return toArrayBuffer(utf8.encode(s));
}

function jsonBase64Url(obj: unknown): string {
    return base64urlEncode(utf8.encode(JSON.stringify(obj)));
}

export async function generateSigningKey(kid: string): Promise<SigningKey> {
    const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: NAMED_CURVE }, true, [
        'sign',
        'verify',
    ])) as webcrypto.CryptoKeyPair;
    const privateJwk = (await subtle.exportKey('jwk', pair.privateKey)) as JWK;
    const publicJwk = (await subtle.exportKey('jwk', pair.publicKey)) as JWK;
    privateJwk.alg = ALG;
    privateJwk.use = 'sig';
    privateJwk.kid = kid;
    publicJwk.alg = ALG;
    publicJwk.use = 'sig';
    publicJwk.kid = kid;
    return { privateJwk, publicJwk, privateKey: pair.privateKey, publicKey: pair.publicKey, kid };
}

export async function importSigningKeyFromPrivateJwk(privateJwk: JWK): Promise<SigningKey> {
    const privateKey = await subtle.importKey(
        'jwk',
        privateJwk as webcrypto.JsonWebKey,
        { name: 'ECDSA', namedCurve: NAMED_CURVE },
        true,
        ['sign'],
    );
    // Strip the private scalar to derive the public JWK. WebCrypto won't import a private JWK
    // with verify usage, so we make a separate import for the public half.
    const { d: _d, ...publicHalf } = privateJwk;
    const publicJwk: JWK = { ...publicHalf, alg: ALG, use: 'sig' };
    const publicKey = await subtle.importKey(
        'jwk',
        publicJwk as webcrypto.JsonWebKey,
        { name: 'ECDSA', namedCurve: NAMED_CURVE },
        true,
        ['verify'],
    );
    return {
        privateJwk,
        publicJwk,
        privateKey,
        publicKey,
        kid: privateJwk.kid ?? '',
    };
}

export interface JWTPayload {
    iss?: string;
    sub?: string;
    aud?: string;
    exp?: number;
    iat?: number;
    scope?: string;
    client_id?: string;
    [k: string]: unknown;
}

export async function signJwt(key: SigningKey, payload: JWTPayload): Promise<string> {
    const header = { alg: ALG, typ: 'JWT', kid: key.kid };
    const headerB64 = jsonBase64Url(header);
    const payloadB64 = jsonBase64Url(payload);
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, ascii(signingInput));
    // WebCrypto returns ECDSA signatures as raw r||s (64 bytes for P-256), which is exactly
    // what JWS expects for ES256 — no DER unwrapping needed.
    return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

export interface VerifyOptions {
    issuer: string;
    audience: string;
}

const decoder = new TextDecoder('utf-8');

export async function verifyJwt(key: SigningKey, token: string, opts: VerifyOptions): Promise<JWTPayload> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed jwt');
    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(decoder.decode(base64urlDecode(headerB64)));
    if (header.alg !== ALG) throw new Error(`unsupported alg ${header.alg}`);

    const ok = await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key.publicKey,
        base64urlDecode(sigB64),
        ascii(`${headerB64}.${payloadB64}`),
    );
    if (!ok) throw new Error('signature verification failed');

    const payload = JSON.parse(decoder.decode(base64urlDecode(payloadB64))) as JWTPayload;
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('jwt expired');
    if (payload.iss !== opts.issuer) throw new Error('jwt iss mismatch');
    if (payload.aud !== opts.audience) throw new Error('jwt aud mismatch');
    return payload;
}

export async function sha256Base64Url(input: string): Promise<string> {
    const digest = await subtle.digest('SHA-256', ascii(input));
    return base64urlEncode(new Uint8Array(digest));
}
