import { randomBytes, randomUUID } from 'node:crypto';
import type { HttpRequest, HttpResponse } from '@scrypted/sdk';
import { sendHtml, sendJson, sendRedirect } from './http-bridge';

// Mirror of @modelcontextprotocol/sdk/server/auth/types#AuthInfo. Inlined rather than imported
// because the MCP SDK ships its types as ESM under typesVersions, and importing them from a
// CommonJS file trips TypeScript's TS1541 (type-only-import-from-ESM-needs-resolution-mode)
// guard. The MCP transport's HandleRequestOptions.authInfo is structurally typed, so a
// matching local declaration plugs in fine.
export interface AuthInfo {
    token: string;
    clientId: string;
    scopes: string[];
    expiresAt?: number;
    resource?: URL;
    extra?: Record<string, unknown>;
}
import {
    generateSigningKey,
    importSigningKeyFromPrivateJwk,
    type JWK,
    type SigningKey,
    sha256Base64Url,
    signJwt,
    verifyJwt,
} from './jwt';

// --- Constants -------------------------------------------------------------

const ACCESS_TOKEN_TTL_SEC = 60 * 60; // 1h
// Refresh tokens are how an MCP client stays connected without re-running the browser-based
// PKCE dance every hour. 30 days is the upper bound on how long a stolen RT remains useful;
// the rotating-on-use store below is what makes that bound tolerable for a public PKCE
// client. (Without rotation, a captured RT would be a 30-day password.)
const REFRESH_TOKEN_TTL_SEC = 30 * 24 * 60 * 60; // 30d
const AUTH_CODE_TTL_MS = 60 * 1000; // 60s — codes are exchanged immediately by the client.
const SUPPORTED_SCOPES = ['mcp'];

// Storage keys. Kept under a namespace so they don't collide with whatever else the plugin
// might persist later.
const STORAGE_KEY_SIGNING_JWK = 'oauth.signing_jwk';
const STORAGE_KEY_CLIENT_PREFIX = 'oauth.client.';
const STORAGE_KEY_REFRESH_TOKEN_PREFIX = 'oauth.rt.';

// --- Types -----------------------------------------------------------------

interface RegisteredClient {
    client_id: string;
    client_id_issued_at: number;
    // Updated on /authorize and on every successful /token grant. Drives the LRU eviction
    // policy when DCR registrations exceed the configured cap. Optional for backward
    // compatibility with records persisted before this field existed — eviction code falls
    // back to client_id_issued_at when missing.
    last_used_at?: number;
    redirect_uris: string[];
    client_name?: string;
    grant_types: string[];
    response_types: string[];
    token_endpoint_auth_method: 'none';
    scope?: string;
}

interface PendingAuthCode {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    codeChallengeMethod: 'S256';
    username: string;
    scope: string;
    expiresAt: number;
}

interface RefreshTokenRecord {
    // The opaque refresh token string. Also used as the storage subkey suffix.
    token: string;
    client_id: string;
    // Username at issuance time. We do NOT re-check admin status on refresh — the chain
    // inherits the /authorize-time admin check. Implication: 30-day TTL is the implicit
    // revocation window if an admin's privileges are revoked. Plugin storage wipe is the
    // hard-revoke escape hatch.
    sub: string;
    scope: string;
    issuedAt: number; // unix sec
    expiresAt: number; // unix sec
}

// Scrypted's Storage interface is the synchronous DOM Storage shape. We need iteration
// (length + key(i)) for the periodic sweepers — both the LRU eviction in ClientStore and
// the expired-RT cleanup in OAuthService — so we widen beyond the basic CRUD trio.
type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'length' | 'key'>;

// Logger shape we accept from the plugin. Scrypted's Console works; so does any object with
// the same .log/.error methods. We use it to surface OAuth failures into the plugin's
// console (visible in the Scrypted UI), since the alternative — silently 401ing — leaves
// the user with nothing to debug.
interface ConsoleLike {
    log(...args: unknown[]): void;
    error(...args: unknown[]): void;
}

// --- Helpers ---------------------------------------------------------------

function base64urlNoPad(buf: Buffer): string {
    return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Build the public origin (e.g. "https://scrypt.local:10443") that the inbound request used,
// so OAuth metadata documents come back with URLs the client can actually hit. Scrypted's
// HttpRequest doesn't carry the protocol directly, so we resolve it independently per axis:
//   - host: prefer `x-forwarded-host`, else the regular `Host` header.
//   - proto: prefer `x-forwarded-proto`, else compare the chosen host's port to
//     SCRYPTED_INSECURE_PORT (default 11080). A match means HTTP; anything else (including
//     the secure default 10443, or an absent port like a behind-a-LB hostname) means HTTPS.
//
// Treating the two headers independently matters because plenty of reverse proxies (nginx
// with the canned `proxy_set_header X-Forwarded-Proto` snippet, Cloudflare, ALB-without-host)
// set proto but leave Host alone. If we required both, those deployments would fall through
// to the port heuristic on the *forwarded* request — which the proxy already rewrote — and
// pick the wrong scheme.
//
// Getting this wrong is fatal: if we advertise https URLs while the client is talking to us
// over http (or vice versa), every metadata fetch fails, the MCP TS SDK falls all the way
// back to `${host}/register`, and the user sees a host-root Express 404.
function originFromRequest(req: HttpRequest): string {
    const headers = req.headers ?? {};
    const xfProto = headers['x-forwarded-proto']?.split(',')[0].trim();
    const xfHost = headers['x-forwarded-host']?.split(',')[0].trim();

    const host = xfHost || headers['host'] || 'localhost';
    if (xfProto) return `${xfProto}://${host}`;

    const insecurePort = Number.parseInt(process.env.SCRYPTED_INSECURE_PORT ?? '11080', 10);
    const portMatch = /:(\d+)$/.exec(host);
    const port = portMatch ? Number.parseInt(portMatch[1], 10) : null;
    const proto = port !== null && port === insecurePort ? 'http' : 'https';
    return `${proto}://${host}`;
}

// Strip the auth-mode suffix off a rootPath so we have the bare plugin endpoint root that
// works for both authenticated and public callers. Examples:
//   "/endpoint/scrypted-mcp"        -> "/endpoint/scrypted-mcp"
//   "/endpoint/scrypted-mcp/public" -> "/endpoint/scrypted-mcp"
function pluginRoot(rootPath: string): string {
    return rootPath.endsWith('/public') ? rootPath.slice(0, -'/public'.length) : rootPath;
}

// Parse a request body into a plain object. Scrypted's HTTP layer always normalizes the
// body for us: globally-installed `bodyParser.urlencoded` / `json` / `raw` middleware
// (see scrypted-server-main.ts) parses the original Content-Type into an object, and
// plugin-http.ts then JSON.stringifies that object before handing it to the plugin. So
// regardless of whether the OAuth client sent JSON (DCR / RFC 7591) or form-encoded
// (`/token` / RFC 6749), what reaches us is the same JSON string.
//
// We try JSON first and fall back to URLSearchParams for the unlikely case of a raw
// form-encoded body that bypassed the normalizer.
function parseBody(body: string | undefined): Record<string, unknown> {
    if (!body) return {};
    try {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            return parsed as Record<string, unknown>;
        }
    } catch {
        // Not JSON — try form-encoded.
    }
    const out: Record<string, string> = {};
    for (const [k, v] of new URLSearchParams(body)) out[k] = v;
    return out;
}

function asString(v: unknown): string | undefined {
    return typeof v === 'string' ? v : undefined;
}

function asStringArray(v: unknown): string[] | undefined {
    return Array.isArray(v) ? v.filter(s => typeof s === 'string') : undefined;
}

// Whitelist redirect_uri schemes allowed at DCR. We restrict to loopback HTTP per RFC 8252:
// `http://localhost`, `http://127.0.0.1`, or `http://[::1]` with any path/port. This is the
// canonical pattern for native MCP clients (Claude Code uses `http://localhost:<random>/callback`).
//
// The reason this is a hard rule rather than a "preferred" one: with auto-approve at /authorize
// + open Dynamic Client Registration, any unrestricted redirect_uri turns into a drive-by-auth
// hole. An attacker registers a client with `redirect_uri = https://attacker.example/cb`, links
// a logged-in admin to /authorize, and the auth code lands at the attacker's URL. PKCE doesn't
// help because the attacker generated the code_challenge during registration. Loopback URIs
// can't easily be impersonated by a remote attacker, so they break the attack chain.
function isAllowedRedirectUri(uri: string): boolean {
    let url: URL;
    try {
        url = new URL(uri);
    } catch {
        return false;
    }
    if (url.protocol !== 'http:') return false;
    const host = url.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

// Reject scopes the AS doesn't advertise. Returning the intersection (rather than the raw
// requested string) means the access token can't claim a scope we never agreed to honor —
// even if no current tool checks scopes, this keeps the door closed for tomorrow.
function intersectScopes(requested: string): string[] {
    return requested.split(/\s+/).filter(s => s && SUPPORTED_SCOPES.includes(s));
}

// --- Stores ----------------------------------------------------------------

// Persistent registry of DCR-registered clients. /register is unauthenticated and
// auto-accepts every request, so we cap the total number of registrations to keep an
// attacker (or a buggy client that re-registers in a loop) from filling plugin storage
// indefinitely. The cap is configurable via the plugin Settings tab.
//
// Eviction policy: LRU keyed by `last_used_at` — the field is touched on every successful
// /authorize and /token grant, so an active client is safe and a dead registration is the
// natural victim. Records missing `last_used_at` (registered before the field existed) fall
// back to `client_id_issued_at` for ordering.
class ClientStore {
    constructor(
        private storage: StorageLike,
        private getMaxClients: () => number,
        private console: ConsoleLike,
    ) {}

    get(clientId: string): RegisteredClient | undefined {
        const raw = this.storage.getItem(STORAGE_KEY_CLIENT_PREFIX + clientId);
        if (!raw) return undefined;
        try {
            return JSON.parse(raw) as RegisteredClient;
        } catch {
            // Persisted record went bad — drop it. The client will re-register on its next
            // attempt because we're a public-client DCR auto-accept AS.
            this.storage.removeItem(STORAGE_KEY_CLIENT_PREFIX + clientId);
            return undefined;
        }
    }

    set(client: RegisteredClient): void {
        // New registration path only — touch() is the update path. Enforce the LRU cap
        // before writing so storage never holds more than `max` entries simultaneously.
        const max = Math.max(1, this.getMaxClients());
        const existing = this.list();
        if (existing.length >= max) {
            // Evict the oldest entries until we have room for one more. Usually drops a
            // single record; the loop covers the case where the cap was lowered via
            // Settings while the store was already over budget.
            const sorted = existing.sort((a, b) => this.lruKey(a) - this.lruKey(b));
            const toEvict = sorted.slice(0, existing.length - max + 1);
            for (const victim of toEvict) {
                this.storage.removeItem(STORAGE_KEY_CLIENT_PREFIX + victim.client_id);
                this.console.log(
                    '[oauth] DCR LRU evict client_id=%s (last_used_at=%d, cap=%d)',
                    victim.client_id,
                    this.lruKey(victim),
                    max,
                );
            }
        }
        this.storage.setItem(STORAGE_KEY_CLIENT_PREFIX + client.client_id, JSON.stringify(client));
    }

    // Update last_used_at on a client without disturbing any other field. Called from
    // /authorize (success) and respondWithTokens (any successful grant) so that the LRU
    // eviction targets actual zombies, not active clients. No-op if the client_id was
    // already evicted or never existed — we don't want to resurrect a deleted record.
    touch(clientId: string): void {
        const existing = this.get(clientId);
        if (!existing) return;
        existing.last_used_at = Math.floor(Date.now() / 1000);
        this.storage.setItem(STORAGE_KEY_CLIENT_PREFIX + clientId, JSON.stringify(existing));
    }

    // Iterate every persisted client. Storage iteration via length+key(i) — see StorageLike
    // for the rationale. Skips entries that fail to parse (corrupt records get cleaned up
    // by get() the next time someone references them).
    private list(): RegisteredClient[] {
        const out: RegisteredClient[] = [];
        try {
            for (let i = 0; i < this.storage.length; i++) {
                const key = this.storage.key(i);
                if (!key || !key.startsWith(STORAGE_KEY_CLIENT_PREFIX)) continue;
                const raw = this.storage.getItem(key);
                if (!raw) continue;
                try {
                    out.push(JSON.parse(raw) as RegisteredClient);
                } catch {
                    // skip — get() will clean up next time
                }
            }
        } catch (e) {
            this.console.error('[oauth] ClientStore.list iteration failed:', e);
        }
        return out;
    }

    private lruKey(c: RegisteredClient): number {
        return c.last_used_at ?? c.client_id_issued_at;
    }
}

class AuthCodeStore {
    private codes = new Map<string, PendingAuthCode>();

    issue(state: PendingAuthCode): string {
        const code = base64urlNoPad(randomBytes(32));
        this.codes.set(code, state);
        // Schedule expiry. We keep this in-memory only — codes are short-lived (60s) and a
        // plugin reload that drops them just forces the client to re-run the dance.
        setTimeout(() => this.codes.delete(code), AUTH_CODE_TTL_MS).unref();
        return code;
    }

    consume(code: string): PendingAuthCode | undefined {
        const entry = this.codes.get(code);
        if (!entry) return undefined;
        this.codes.delete(code);
        if (entry.expiresAt < Date.now()) return undefined;
        return entry;
    }
}

// Refresh tokens are persisted to plugin storage so they survive plugin reloads (otherwise a
// reload mid-session would silently invalidate every refresh chain). One key per token; the
// storage value is the JSON record.
//
// Rotation: every consume() deletes the record before returning it, and the caller is
// expected to issue a fresh one. Two presentations of the same RT will see at most one hit
// — the second presentation (whether from a network retry by the legitimate client, or a
// thief who captured the RT after the legit client already used it) just looks like an
// invalid_grant. The legitimate client then re-runs PKCE, which surfaces the breach to the
// user. This is the OAuth 2.1 §4.3.1 / RFC 6749 §10.4 recommendation, simplified — we don't
// track replacement chains, so we can't proactively revoke the entire chain on detection;
// the natural "re-auth on failure" loop is the best we offer at v1.
class RefreshTokenStore {
    constructor(
        private storage: StorageLike,
        private console: ConsoleLike,
    ) {}

    issue(seed: Omit<RefreshTokenRecord, 'token'>): string {
        const token = base64urlNoPad(randomBytes(32));
        const record: RefreshTokenRecord = { token, ...seed };
        this.storage.setItem(STORAGE_KEY_REFRESH_TOKEN_PREFIX + token, JSON.stringify(record));
        return token;
    }

    // Returns the record only if found, valid, and bound to the submitted client_id. Always
    // deletes the record on first sight — caller is responsible for issuing a replacement.
    consume(token: string, clientId: string): RefreshTokenRecord | undefined {
        const key = STORAGE_KEY_REFRESH_TOKEN_PREFIX + token;
        const raw = this.storage.getItem(key);
        if (!raw) return undefined;
        this.storage.removeItem(key);
        let record: RefreshTokenRecord;
        try {
            record = JSON.parse(raw) as RefreshTokenRecord;
        } catch {
            this.console.error('[oauth] refresh token record corrupt for prefix=%s', token.slice(0, 6));
            return undefined;
        }
        if (record.client_id !== clientId) return undefined;
        if (record.expiresAt <= Math.floor(Date.now() / 1000)) return undefined;
        return record;
    }

    // Drop expired records. Without this, RTs issued for clients that never come back to
    // refresh sit in storage for a full TTL (30d) at minimum, and rotated-but-uncollected
    // records (write-then-overwrite) accumulate behind any consume()-only access pattern.
    // Returns the count for logging.
    sweepExpired(): number {
        const now = Math.floor(Date.now() / 1000);
        const toDelete: string[] = [];
        try {
            for (let i = 0; i < this.storage.length; i++) {
                const key = this.storage.key(i);
                if (!key || !key.startsWith(STORAGE_KEY_REFRESH_TOKEN_PREFIX)) continue;
                const raw = this.storage.getItem(key);
                if (!raw) continue;
                try {
                    const record = JSON.parse(raw) as RefreshTokenRecord;
                    if (record.expiresAt <= now) toDelete.push(key);
                } catch {
                    // Corrupt record — also a cleanup candidate. We'd rather lose a malformed
                    // RT than carry it forever.
                    toDelete.push(key);
                }
            }
        } catch (e) {
            this.console.error('[oauth] RefreshTokenStore.sweepExpired iteration failed:', e);
            return 0;
        }
        for (const key of toDelete) this.storage.removeItem(key);
        return toDelete.length;
    }
}

// --- Signing key -----------------------------------------------------------

async function loadOrCreateSigningKey(storage: StorageLike): Promise<SigningKey> {
    const raw = storage.getItem(STORAGE_KEY_SIGNING_JWK);
    if (raw) {
        try {
            const privateJwk = JSON.parse(raw) as JWK;
            return await importSigningKeyFromPrivateJwk(privateJwk);
        } catch {
            // Persisted key is corrupt — fall through and regenerate. Old tokens become
            // unverifiable, which forces clients through the OAuth flow again. That's fine
            // for a v1 — corrupt key is rare and re-auth is cheap.
        }
    }
    const key = await generateSigningKey(randomUUID());
    storage.setItem(STORAGE_KEY_SIGNING_JWK, JSON.stringify(key.privateJwk));
    return key;
}

// --- OAuthService ----------------------------------------------------------

export interface OAuthServiceOptions {
    storage: StorageLike;
    console: ConsoleLike;
    // Reads the configured DCR client cap from plugin storage. Called per /register so a
    // settings change applies on the next registration without a plugin reload.
    getMaxClients: () => number;
}

// How often the expired-RT sweeper runs. 30 minutes is short enough that storage doesn't
// drift and long enough that the sweep cost (O(N) over plugin storage keys) is negligible.
const REFRESH_TOKEN_SWEEP_INTERVAL_MS = 30 * 60 * 1000;

export class OAuthService {
    private storage: StorageLike;
    private clients: ClientStore;
    private codes = new AuthCodeStore();
    private refreshTokens: RefreshTokenStore;
    private signing: Promise<SigningKey>;
    private console: ConsoleLike;

    constructor(opts: OAuthServiceOptions) {
        this.console = opts.console;
        this.storage = opts.storage;
        this.clients = new ClientStore(opts.storage, opts.getMaxClients, opts.console);
        this.refreshTokens = new RefreshTokenStore(opts.storage, opts.console);
        this.signing = loadOrCreateSigningKey(opts.storage);
        // Fire-and-forget the periodic RT cleanup. unref() so the timer doesn't keep the
        // event loop alive on its own (in-process plugin runs forever anyway, but unref is
        // the polite default).
        setInterval(() => {
            const dropped = this.refreshTokens.sweepExpired();
            if (dropped > 0) this.console.log('[oauth] swept %d expired refresh token(s)', dropped);
        }, REFRESH_TOKEN_SWEEP_INTERVAL_MS).unref();
    }

    // Counts persisted OAuth records by prefix. Used by the Settings UI to show a
    // health snapshot without exposing the records themselves.
    getStats(): { clients: number; refreshTokens: number } {
        let clients = 0;
        let refreshTokens = 0;
        try {
            for (let i = 0; i < this.storage.length; i++) {
                const k = this.storage.key(i);
                if (!k) continue;
                if (k.startsWith(STORAGE_KEY_CLIENT_PREFIX)) clients++;
                else if (k.startsWith(STORAGE_KEY_REFRESH_TOKEN_PREFIX)) refreshTokens++;
            }
        } catch (e) {
            this.console.error('[oauth] getStats iteration failed:', e);
        }
        return { clients, refreshTokens };
    }

    // Hard revoke, surfaced via the plugin's "Revoke all tokens" Settings button. Drops
    // every persisted refresh token, deletes every DCR client registration, rotates the
    // JWT signing key (so previously-issued access tokens immediately stop verifying), and
    // resets the in-memory auth-code store. Caller is responsible for closing live MCP
    // sessions — this method only handles state owned by OAuthService.
    //
    // After this, any active client will see 401s on its next request and have to re-run
    // DCR + PKCE from scratch.
    async revokeAll(): Promise<{ clients: number; refreshTokens: number }> {
        const counts = { clients: 0, refreshTokens: 0 };
        const keysToRemove: string[] = [];
        try {
            for (let i = 0; i < this.storage.length; i++) {
                const k = this.storage.key(i);
                if (!k) continue;
                if (k.startsWith(STORAGE_KEY_CLIENT_PREFIX)) {
                    keysToRemove.push(k);
                    counts.clients++;
                } else if (k.startsWith(STORAGE_KEY_REFRESH_TOKEN_PREFIX)) {
                    keysToRemove.push(k);
                    counts.refreshTokens++;
                }
            }
        } catch (e) {
            this.console.error('[oauth] revokeAll iteration failed:', e);
            throw e;
        }
        for (const k of keysToRemove) this.storage.removeItem(k);
        // Rotate the signing key. Removing the persisted JWK and re-running
        // loadOrCreateSigningKey forces generation of a fresh EC P-256 pair, which means
        // every still-unexpired access token (1h TTL) suddenly fails JWS verification.
        // Without this, an AT issued one second before the revoke would keep working for
        // ~59 minutes. Awaited so we surface key-generation errors here rather than at the
        // next inbound request.
        this.storage.removeItem(STORAGE_KEY_SIGNING_JWK);
        this.signing = loadOrCreateSigningKey(this.storage);
        await this.signing;
        // In-memory auth codes are short-lived (60s) but a thorough revoke includes them.
        this.codes = new AuthCodeStore();
        this.console.log(
            '[oauth] revokeAll: removed %d clients + %d refresh tokens, rotated signing key',
            counts.clients,
            counts.refreshTokens,
        );
        return counts;
    }

    // Compute paths for this request's perspective (origin + plugin root). Centralised
    // because every metadata document has to advertise URLs that match the inbound caller.
    //
    // Everything lives under /public/ — including the issuer. The MCP TS SDK derives the AS
    // metadata URL by appending `.well-known/oauth-authorization-server` to the issuer; if
    // the issuer were the bare plugin endpoint, that lookup would land on the authenticated
    // path and Scrypted would 401 it before our handler ran, causing the client to fall back
    // to `${origin}/register` and hit Scrypted's root 404.
    //
    // /authorize is on the public path too. Scrypted's auth middleware still reads the
    // session cookie and populates `request.username` for public endpoints — it just doesn't
    // *enforce* the cookie there (`plugin-http.ts:89` only 401s non-public). So a logged-in
    // browser still gets auto-approved, and an unauthenticated browser gets our friendly
    // "log in first" page instead of Scrypted's plain-text 401.
    private endpoints(req: HttpRequest) {
        const origin = originFromRequest(req);
        const root = pluginRoot(req.rootPath ?? '/endpoint/scrypted-mcp');
        const base = `${origin}${root}/public`;
        return {
            origin,
            issuer: `${base}/`,
            authorization_endpoint: `${base}/authorize`,
            token_endpoint: `${base}/token`,
            registration_endpoint: `${base}/register`,
            jwks_uri: `${base}/.well-known/jwks.json`,
            authorization_server_metadata: `${base}/.well-known/oauth-authorization-server`,
            protected_resource_metadata: `${base}/.well-known/oauth-protected-resource`,
            // The MCP endpoint itself, used as the resource URI in tokens and metadata.
            resource: `${base}/mcp`,
        };
    }

    // Public path matcher. main.ts calls this for every inbound request; if it returns true,
    // the request was an OAuth surface request and we've already populated the response.
    async handle(req: HttpRequest, res: HttpResponse): Promise<boolean> {
        const url = new URL(req.url ?? '/', 'http://x');
        const root = pluginRoot(req.rootPath ?? '/');
        // Strip the rootPath prefix so we match on the local subpath (/authorize, /token, ...).
        // Scrypted's `req.url` includes the full prefix; the public-or-not flag is in
        // isPublicEndpoint, which we use as a sanity check below.
        let local = url.pathname;
        if (local.startsWith(root)) local = local.slice(root.length);
        if (req.isPublicEndpoint && local.startsWith('/public')) local = local.slice('/public'.length);
        if (!local.startsWith('/')) local = '/' + local;

        switch (local) {
            case '/.well-known/oauth-authorization-server':
                this.serveAuthorizationServerMetadata(req, res);
                return true;
            // The MCP TS SDK's `buildDiscoveryUrls` (`client/auth.js:575`) tries three URLs
            // when discovering AS metadata for an issuer with a path: two at the host root
            // and one at `${issuer.pathname}/.well-known/openid-configuration`. Only the
            // last one can actually reach a Scrypted plugin endpoint, so we serve it too —
            // with the same OAuth document plus the bare-minimum OIDC fields the schema
            // requires (subject_types_supported, id_token_signing_alg_values_supported).
            case '/.well-known/openid-configuration':
                this.serveOpenIdMetadata(req, res);
                return true;
            case '/.well-known/oauth-protected-resource':
                this.serveProtectedResourceMetadata(req, res);
                return true;
            case '/.well-known/jwks.json':
                await this.serveJwks(req, res);
                return true;
            case '/register':
                await this.handleRegister(req, res);
                return true;
            case '/token':
                await this.handleToken(req, res);
                return true;
            case '/authorize':
                await this.handleAuthorize(req, res);
                return true;
            default:
                return false;
        }
    }

    // 401 helper used by main.ts on /mcp when Bearer auth fails. The header points at our
    // protected-resource metadata so a spec-compliant MCP client can discover the AS and
    // start the OAuth dance.
    challengeFor(req: HttpRequest): { status: number; headers: Record<string, string>; body: string } {
        const ep = this.endpoints(req);
        return {
            status: 401,
            headers: {
                'Content-Type': 'application/json',
                'WWW-Authenticate': `Bearer resource_metadata="${ep.protected_resource_metadata}"`,
            },
            body: JSON.stringify({ error: 'unauthorized', error_description: 'Bearer token required' }),
        };
    }

    // Bearer token verification — used by main.ts before forwarding to the MCP transport.
    async verifyBearer(req: HttpRequest): Promise<AuthInfo | undefined> {
        const auth = req.headers?.['authorization'];
        if (!auth) return undefined;
        const m = /^Bearer\s+(.+)$/i.exec(auth);
        if (!m) {
            // Don't log the header value: when the regex fails on something like
            // "Bearer\nxyz..." (rare, but possible with unusual whitespace) the contents
            // can include real token bytes. Operators only need to know it was malformed,
            // not what was in it. Log the length so a "consistently zero-length" pattern
            // is still visible.
            this.console.error('[oauth] Bearer header present but malformed (length=%d)', auth.length);
            return undefined;
        }
        const token = m[1];
        const ep = this.endpoints(req);
        try {
            const key = await this.signing;
            const payload = await verifyJwt(key, token, { issuer: ep.issuer, audience: ep.resource });
            const scopes =
                typeof payload.scope === 'string' ? payload.scope.split(/\s+/).filter(Boolean) : SUPPORTED_SCOPES;
            return {
                token,
                clientId: typeof payload.client_id === 'string' ? payload.client_id : 'unknown',
                scopes,
                expiresAt: payload.exp,
                resource: payload.aud ? new URL(String(payload.aud)) : undefined,
                extra: { sub: payload.sub },
            };
        } catch (e: any) {
            // Decode the payload (without re-verifying) just to surface the iss/aud the client
            // sent so the operator can see exactly which check failed and what to realign.
            // The signature was already validated or rejected above; this decode is purely
            // for diagnostics on a token we just decided is bad.
            let decoded: { iss?: unknown; aud?: unknown; sub?: unknown; exp?: unknown } | undefined;
            try {
                const parts = token.split('.');
                if (parts.length === 3) {
                    decoded = JSON.parse(
                        Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'),
                    );
                }
            } catch {
                // best-effort
            }
            this.console.error('[oauth] bearer verification failed:', e?.message ?? String(e));
            this.console.error('[oauth]   expected iss=%s aud=%s', ep.issuer, ep.resource);
            this.console.error(
                '[oauth]   token    iss=%s aud=%s sub=%s exp=%s',
                decoded?.iss,
                decoded?.aud,
                decoded?.sub,
                decoded?.exp,
            );
            return undefined;
        }
    }

    // --- Metadata documents ------------------------------------------------

    private serveAuthorizationServerMetadata(req: HttpRequest, res: HttpResponse) {
        const ep = this.endpoints(req);
        sendJson(res, 200, {
            issuer: ep.issuer,
            authorization_endpoint: ep.authorization_endpoint,
            token_endpoint: ep.token_endpoint,
            registration_endpoint: ep.registration_endpoint,
            jwks_uri: ep.jwks_uri,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'refresh_token'],
            code_challenge_methods_supported: ['S256'],
            token_endpoint_auth_methods_supported: ['none'],
            scopes_supported: SUPPORTED_SCOPES,
        });
    }

    // OpenID Connect Discovery metadata, served as the only AS-discovery URL the MCP TS SDK
    // tries that lands on our plugin endpoint. We don't actually issue id_tokens — the OIDC
    // fields below are the minimum the SDK's `OpenIdProviderDiscoveryMetadataSchema`
    // (`shared/auth.js:137`) needs to accept the document. The rest mirrors the OAuth doc.
    private serveOpenIdMetadata(req: HttpRequest, res: HttpResponse) {
        const ep = this.endpoints(req);
        sendJson(res, 200, {
            issuer: ep.issuer,
            authorization_endpoint: ep.authorization_endpoint,
            token_endpoint: ep.token_endpoint,
            registration_endpoint: ep.registration_endpoint,
            jwks_uri: ep.jwks_uri,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'refresh_token'],
            code_challenge_methods_supported: ['S256'],
            token_endpoint_auth_methods_supported: ['none'],
            scopes_supported: SUPPORTED_SCOPES,
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['ES256'],
        });
    }

    private serveProtectedResourceMetadata(req: HttpRequest, res: HttpResponse) {
        const ep = this.endpoints(req);
        sendJson(res, 200, {
            resource: ep.resource,
            authorization_servers: [ep.issuer],
            scopes_supported: SUPPORTED_SCOPES,
            bearer_methods_supported: ['header'],
        });
    }

    private async serveJwks(_req: HttpRequest, res: HttpResponse) {
        const key = await this.signing;
        sendJson(res, 200, { keys: [key.publicJwk] });
    }

    // --- DCR (RFC 7591) ---------------------------------------------------

    private async handleRegister(req: HttpRequest, res: HttpResponse) {
        if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
            sendJson(res, 405, { error: 'method_not_allowed' });
            return;
        }
        const body = parseBody(req.body);

        const redirectUris = asStringArray(body.redirect_uris) ?? [];
        if (redirectUris.length === 0) {
            sendJson(res, 400, {
                error: 'invalid_redirect_uri',
                error_description: 'at least one redirect_uri required',
            });
            return;
        }
        const badUris = redirectUris.filter(u => !isAllowedRedirectUri(u));
        if (badUris.length > 0) {
            sendJson(res, 400, {
                error: 'invalid_redirect_uri',
                error_description:
                    'redirect_uri must be loopback HTTP (http://localhost, http://127.0.0.1, or http://[::1]); rejected: ' +
                    badUris.join(', '),
            });
            return;
        }

        const grantTypes = asStringArray(body.grant_types) ?? ['authorization_code'];
        if (!grantTypes.includes('authorization_code')) {
            sendJson(res, 400, {
                error: 'invalid_client_metadata',
                error_description: 'authorization_code grant required',
            });
            return;
        }

        const client: RegisteredClient = {
            client_id: randomUUID(),
            client_id_issued_at: Math.floor(Date.now() / 1000),
            redirect_uris: redirectUris,
            client_name: asString(body.client_name),
            grant_types: grantTypes,
            response_types: asStringArray(body.response_types) ?? ['code'],
            // We are a public-client AS — PKCE-only, no client_secret. Anything else would be
            // dishonest because we can't actually authenticate the client.
            token_endpoint_auth_method: 'none',
            scope: asString(body.scope) ?? SUPPORTED_SCOPES.join(' '),
        };
        this.clients.set(client);
        this.console.log(
            '[oauth] DCR registered client_id=%s name=%s',
            client.client_id,
            client.client_name ?? '(unnamed)',
        );
        sendJson(res, 201, client);
    }

    // --- Authorization endpoint -------------------------------------------

    private async handleAuthorize(req: HttpRequest, res: HttpResponse) {
        // Scrypted's auth pipeline populates `username` from the session cookie regardless of
        // public/authenticated routing. Missing `username` means the user isn't signed in.
        if (!req.username) {
            sendHtml(res, 401, renderUnauthorizedPage(), { 'WWW-Authenticate': 'Cookie' });
            return;
        }
        // MCP exposes admin-grade tools (restore_backup, set_dotenv, restart_server, ...).
        // Lock the AS to Scrypted admins — `aclId` is undefined for env-admin/passwd-admin
        // sessions and set to a device id for ACL-restricted users.
        if (req.aclId) {
            sendHtml(
                res,
                403,
                renderErrorPage(
                    'Admin access required',
                    'The Scrypted MCP plugin only authorizes Scrypted admin users. Sign in as an admin and retry.',
                ),
            );
            return;
        }

        const url = new URL(req.url ?? '/', 'http://x');
        const params = url.searchParams;
        const clientId = params.get('client_id') ?? '';
        const redirectUri = params.get('redirect_uri') ?? '';
        const responseType = params.get('response_type') ?? '';
        const codeChallenge = params.get('code_challenge') ?? '';
        const codeChallengeMethod = params.get('code_challenge_method') ?? '';
        const state = params.get('state') ?? '';
        const scopeParam = params.get('scope') ?? SUPPORTED_SCOPES.join(' ');
        const resourceParam = params.get('resource');

        const client = this.clients.get(clientId);
        if (!client) {
            sendHtml(
                res,
                400,
                renderErrorPage('Unknown client_id', 'The client_id was not recognized. Re-register and try again.'),
            );
            return;
        }
        if (!client.redirect_uris.includes(redirectUri)) {
            sendHtml(
                res,
                400,
                renderErrorPage(
                    'Bad redirect_uri',
                    'The redirect_uri does not match any registered URI for this client.',
                ),
            );
            return;
        }
        // From here on we have a trusted redirect target; OAuth errors travel back via that
        // URI rather than displayed inline. Spec-compliant.
        const redirectError = (error: string, description: string) => {
            const u = new URL(redirectUri);
            u.searchParams.set('error', error);
            u.searchParams.set('error_description', description);
            if (state) u.searchParams.set('state', state);
            sendRedirect(res, u.toString());
        };
        if (responseType !== 'code') {
            redirectError('unsupported_response_type', 'only response_type=code is supported');
            return;
        }
        if (!codeChallenge || codeChallengeMethod !== 'S256') {
            redirectError('invalid_request', 'PKCE with code_challenge_method=S256 is required');
            return;
        }
        const scopes = intersectScopes(scopeParam);
        if (scopes.length === 0) {
            redirectError(
                'invalid_scope',
                `none of the requested scopes are supported (supported: ${SUPPORTED_SCOPES.join(', ')})`,
            );
            return;
        }
        const scope = scopes.join(' ');

        // RFC 8707: clients can pin a target resource. We only have one — the /mcp endpoint
        // — and the issued JWT's `aud` claim is always set to that. If a client sends
        // anything else, fail loud with `invalid_target` instead of silently substituting
        // ours; otherwise the auth code's bound resource and the token's `aud` would
        // diverge in ways the client couldn't observe.
        const ep = this.endpoints(req);
        if (resourceParam !== null && resourceParam !== ep.resource) {
            redirectError(
                'invalid_target',
                `resource must equal "${ep.resource}" (the only resource this AS issues tokens for)`,
            );
            return;
        }

        // Auto-approve — option (a) per the design discussion. The user's Scrypted session
        // is the proof that they meant to grant this. No consent screen.
        const code = this.codes.issue({
            clientId,
            redirectUri,
            codeChallenge,
            codeChallengeMethod: 'S256',
            username: req.username,
            scope,
            expiresAt: Date.now() + AUTH_CODE_TTL_MS,
        });
        // Touch the LRU stamp so an active client doesn't get evicted during a busy /register
        // burst from another client.
        this.clients.touch(clientId);
        this.console.log(
            '[oauth] /authorize approved user=%s client_id=%s redirect_uri=%s',
            req.username,
            clientId,
            redirectUri,
        );
        const target = new URL(redirectUri);
        target.searchParams.set('code', code);
        if (state) target.searchParams.set('state', state);
        sendRedirect(res, target.toString());
    }

    // --- Token endpoint ---------------------------------------------------

    // Dispatcher. Splits authorization_code (initial grant) and refresh_token (rotating
    // re-authentication for an already-paired client) into separate handlers — the two
    // share enough validation to confuse the trace if they're inlined together.
    private async handleToken(req: HttpRequest, res: HttpResponse) {
        if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
            this.console.error('[oauth] /token reject: method_not_allowed', req.method);
            sendJson(res, 405, { error: 'method_not_allowed' });
            return;
        }
        const body = parseBody(req.body);
        const grantType = asString(body.grant_type);
        if (grantType === 'authorization_code') {
            await this.handleAuthorizationCodeGrant(req, res, body);
            return;
        }
        if (grantType === 'refresh_token') {
            await this.handleRefreshTokenGrant(req, res, body);
            return;
        }
        this.console.error('[oauth] /token reject: unsupported_grant_type', grantType);
        sendJson(res, 400, { error: 'unsupported_grant_type' });
    }

    private async handleAuthorizationCodeGrant(req: HttpRequest, res: HttpResponse, body: Record<string, unknown>) {
        const code = asString(body.code);
        const codeVerifier = asString(body.code_verifier);
        const clientId = asString(body.client_id);
        const redirectUri = asString(body.redirect_uri);
        // OAuth 2.1 / RFC 6749 §4.1.3: when redirect_uri was sent at /authorize (which we
        // require — see handleAuthorize), it MUST be sent at /token and match exactly. The
        // earlier "only check if present" pass would let a token request through with a
        // missing redirect_uri, weakening the binding between the auth code and the
        // redirect target it was issued for.
        if (!code || !codeVerifier || !clientId || !redirectUri) {
            this.console.error(
                '[oauth] /token reject: invalid_request — has code=%s code_verifier=%s client_id=%s redirect_uri=%s',
                !!code,
                !!codeVerifier,
                !!clientId,
                !!redirectUri,
            );
            sendJson(res, 400, { error: 'invalid_request' });
            return;
        }
        const client = this.clients.get(clientId);
        if (!client) {
            this.console.error('[oauth] /token reject: invalid_client (unknown client_id=%s)', clientId);
            sendJson(res, 401, { error: 'invalid_client' });
            return;
        }
        const pending = this.codes.consume(code);
        if (!pending) {
            // Most common cause: plugin reloaded between /authorize and /token (in-memory
            // code store was wiped), or the SDK retried after the 60s TTL elapsed.
            this.console.error('[oauth] /token reject: invalid_grant — code not found / expired (client=%s)', clientId);
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'code not found or expired' });
            return;
        }
        if (pending.clientId !== clientId) {
            this.console.error(
                '[oauth] /token reject: invalid_grant — code/client mismatch (code-bound=%s submitted=%s)',
                pending.clientId,
                clientId,
            );
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'client_id does not match code' });
            return;
        }
        if (redirectUri !== pending.redirectUri) {
            this.console.error(
                '[oauth] /token reject: invalid_grant — redirect_uri mismatch (expected=%s got=%s)',
                pending.redirectUri,
                redirectUri,
            );
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
            return;
        }
        // PKCE check.
        const expected = await sha256Base64Url(codeVerifier);
        if (expected !== pending.codeChallenge) {
            this.console.error(
                '[oauth] /token reject: PKCE failed — expected challenge=%s got computed=%s (verifier len=%d)',
                pending.codeChallenge,
                expected,
                codeVerifier.length,
            );
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
            return;
        }

        await this.respondWithTokens(req, res, {
            sub: pending.username,
            scope: pending.scope,
            clientId,
        });
    }

    private async handleRefreshTokenGrant(req: HttpRequest, res: HttpResponse, body: Record<string, unknown>) {
        const refreshToken = asString(body.refresh_token);
        const clientId = asString(body.client_id);
        if (!refreshToken || !clientId) {
            this.console.error(
                '[oauth] /token refresh reject: invalid_request — has refresh_token=%s client_id=%s',
                !!refreshToken,
                !!clientId,
            );
            sendJson(res, 400, { error: 'invalid_request' });
            return;
        }
        const client = this.clients.get(clientId);
        if (!client) {
            this.console.error('[oauth] /token refresh reject: invalid_client (unknown client_id=%s)', clientId);
            sendJson(res, 401, { error: 'invalid_client' });
            return;
        }
        const record = this.refreshTokens.consume(refreshToken, clientId);
        if (!record) {
            // Could be: expired, never existed, replayed (already consumed by previous use),
            // or bound to a different client_id. We deliberately don't distinguish — the
            // client just re-runs PKCE.
            this.console.error(
                '[oauth] /token refresh reject: invalid_grant — refresh_token unknown / expired / wrong client (client_id=%s)',
                clientId,
            );
            sendJson(res, 400, { error: 'invalid_grant', error_description: 'refresh_token invalid or expired' });
            return;
        }
        // RFC 6749 §6 lets the client request a *narrower* scope on refresh. We accept any
        // subset of the original; anything else gets rejected so a buggy client doesn't
        // silently lose authorization it thought it kept.
        let scope = record.scope;
        const requestedScope = asString(body.scope);
        if (requestedScope) {
            const requestedSet = requestedScope.split(/\s+/).filter(Boolean);
            const originalSet = new Set(record.scope.split(/\s+/).filter(Boolean));
            if (!requestedSet.every(s => originalSet.has(s)) || requestedSet.length === 0) {
                sendJson(res, 400, {
                    error: 'invalid_scope',
                    error_description: 'requested scope must be a non-empty subset of the original grant',
                });
                return;
            }
            scope = requestedSet.join(' ');
        }
        await this.respondWithTokens(req, res, {
            sub: record.sub,
            scope,
            clientId,
        });
    }

    // Issues a fresh access_token + refresh_token pair. Used by both the authorization_code
    // and refresh_token grants. Refresh tokens are rotating: every issuance produces a new
    // RT, and the previous one was already deleted by RefreshTokenStore.consume(). The
    // client must store the new `refresh_token` from each /token response.
    //
    // We do NOT re-check whether the user is still a Scrypted admin here — admin status is
    // validated at /authorize, and the refresh chain inherits that decision until the 30-day
    // TTL elapses. If you need to hard-revoke a chain, wipe the plugin's storage (signing
    // key + DCR registrations + RTs all live there).
    private async respondWithTokens(
        req: HttpRequest,
        res: HttpResponse,
        seed: { sub: string; scope: string; clientId: string },
    ) {
        const ep = this.endpoints(req);
        const key = await this.signing;
        const now = Math.floor(Date.now() / 1000);
        const accessToken = await signJwt(key, {
            iss: ep.issuer,
            sub: seed.sub,
            aud: ep.resource,
            iat: now,
            exp: now + ACCESS_TOKEN_TTL_SEC,
            scope: seed.scope,
            client_id: seed.clientId,
        });
        const refreshToken = this.refreshTokens.issue({
            client_id: seed.clientId,
            sub: seed.sub,
            scope: seed.scope,
            issuedAt: now,
            expiresAt: now + REFRESH_TOKEN_TTL_SEC,
        });
        // Touch the LRU stamp on every successful grant so the client doesn't get evicted
        // mid-session by a /register burst from a different client.
        this.clients.touch(seed.clientId);
        this.console.log(
            '[oauth] /token issued user=%s client_id=%s aud=%s access_exp=%d refresh_exp=%d',
            seed.sub,
            seed.clientId,
            ep.resource,
            now + ACCESS_TOKEN_TTL_SEC,
            now + REFRESH_TOKEN_TTL_SEC,
        );
        sendJson(
            res,
            200,
            {
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: ACCESS_TOKEN_TTL_SEC,
                scope: seed.scope,
                refresh_token: refreshToken,
            },
            { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
        );
    }
}

// --- HTML helpers (kept inline so the plugin is one self-contained npm package) -----

function renderUnauthorizedPage(): string {
    return `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in to Scrypted</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:540px;margin:6rem auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px}</style></head>
<body>
<h1>Sign in to Scrypted to continue</h1>
<p>The Scrypted MCP plugin authorizes access using your Scrypted user account. Open the Scrypted UI in this browser, sign in, then retry the connection from your MCP client.</p>
</body></html>`;
}

function renderErrorPage(title: string, body: string): string {
    return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:540px;margin:6rem auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}</style></head>
<body><h1>${title}</h1><p>${body}</p></body></html>`;
}
