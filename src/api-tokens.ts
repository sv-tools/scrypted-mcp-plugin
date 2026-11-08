import { createHash, randomBytes, randomUUID } from 'node:crypto';

// Static API tokens — the non-OAuth way to authenticate to /mcp.
//
// Why they exist: MCP clients refuse to run the OAuth token exchange over plain HTTP unless
// the host is loopback (Claude Code: "OAuth token requests MUST use TLS (localhost /
// 127.0.0.1 / ::1 are exempt)"). Most Scrypted installs are reached at
// http://<lan-ip>:11080 or https://<lan-ip>:10443 with a self-signed cert, so OAuth is
// unusable for them. A static token sent as `Authorization: Bearer <token>` never triggers a
// 401, so the client never starts OAuth, and plain HTTP works.
//
// Storage: only the SHA-256 of the token is persisted, keyed by that hash, so lookup is a
// single getItem and the plaintext never touches disk. The plaintext is shown once in the
// Settings UI (held in memory by the plugin) right after creation.

export const API_TOKEN_PREFIX = 'smcp_';
const STORAGE_KEY_API_TOKEN_PREFIX = 'apitoken.';
// lastUsedAt is informational only; throttle the write so a busy client doesn't turn every
// request into a storage write.
const LAST_USED_WRITE_INTERVAL_SEC = 60;
export const API_TOKEN_NAME_MAX_LEN = 64;

export interface ApiTokenRecord {
    // Short random id. Shown in the Settings UI to disambiguate tokens with the same name.
    id: string;
    name: string;
    createdAt: number; // unix sec
    lastUsedAt?: number; // unix sec
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'length' | 'key'>;

interface ConsoleLike {
    log(...args: unknown[]): void;
    error(...args: unknown[]): void;
}

function hashToken(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function isApiTokenFormat(token: string): boolean {
    return token.startsWith(API_TOKEN_PREFIX);
}

export class ApiTokenStore {
    constructor(
        private storage: StorageLike,
        private console: ConsoleLike,
    ) {}

    // Creates a token and returns the plaintext. The caller must show it to the operator
    // immediately: it can't be recovered later.
    create(rawName: string): { token: string; record: ApiTokenRecord } {
        const name = rawName.trim();
        if (!name) throw new Error('API token name must not be empty');
        if (name.length > API_TOKEN_NAME_MAX_LEN) {
            throw new Error(`API token name must be at most ${API_TOKEN_NAME_MAX_LEN} characters`);
        }
        const token = API_TOKEN_PREFIX + randomBytes(32).toString('base64url');
        const record: ApiTokenRecord = {
            id: randomUUID().slice(0, 8),
            name,
            createdAt: Math.floor(Date.now() / 1000),
        };
        this.storage.setItem(STORAGE_KEY_API_TOKEN_PREFIX + hashToken(token), JSON.stringify(record));
        this.console.log('[api-tokens] created token name=%s id=%s', record.name, record.id);
        return { token, record };
    }

    // Returns the record if the token is known, updating lastUsedAt (throttled).
    verify(token: string): ApiTokenRecord | undefined {
        if (!isApiTokenFormat(token)) return undefined;
        const key = STORAGE_KEY_API_TOKEN_PREFIX + hashToken(token);
        const raw = this.storage.getItem(key);
        if (!raw) return undefined;
        let record: ApiTokenRecord;
        try {
            record = JSON.parse(raw) as ApiTokenRecord;
        } catch {
            this.console.error('[api-tokens] corrupt token record, ignoring');
            return undefined;
        }
        const now = Math.floor(Date.now() / 1000);
        if (!record.lastUsedAt || now - record.lastUsedAt >= LAST_USED_WRITE_INTERVAL_SEC) {
            record.lastUsedAt = now;
            this.storage.setItem(key, JSON.stringify(record));
        }
        return record;
    }

    list(): ApiTokenRecord[] {
        return this.entries()
            .map(e => e.record)
            .sort((a, b) => a.createdAt - b.createdAt);
    }

    // Revokes every token whose id is not in keepIds. Returns the revoked records.
    retainOnly(keepIds: Set<string>): ApiTokenRecord[] {
        const revoked: ApiTokenRecord[] = [];
        for (const { key, record } of this.entries()) {
            if (keepIds.has(record.id)) continue;
            this.storage.removeItem(key);
            revoked.push(record);
            this.console.log('[api-tokens] revoked token name=%s id=%s', record.name, record.id);
        }
        return revoked;
    }

    revokeAll(): number {
        return this.retainOnly(new Set()).length;
    }

    count(): number {
        return this.entries().length;
    }

    private entries(): { key: string; record: ApiTokenRecord }[] {
        const out: { key: string; record: ApiTokenRecord }[] = [];
        try {
            for (let i = 0; i < this.storage.length; i++) {
                const key = this.storage.key(i);
                if (!key || !key.startsWith(STORAGE_KEY_API_TOKEN_PREFIX)) continue;
                const raw = this.storage.getItem(key);
                if (!raw) continue;
                try {
                    out.push({ key, record: JSON.parse(raw) as ApiTokenRecord });
                } catch {
                    // Corrupt record: surface it with a placeholder so it can still be revoked.
                    out.push({ key, record: { id: key.slice(-8), name: '(corrupt)', createdAt: 0 } });
                }
            }
        } catch (e) {
            this.console.error('[api-tokens] storage iteration failed:', e);
        }
        return out;
    }
}

// Label shown in the Settings multi-select. Must embed the id: putSetting gets the labels
// back and we parse the id out to decide what to keep.
export function apiTokenLabel(record: ApiTokenRecord): string {
    const created = record.createdAt ? new Date(record.createdAt * 1000).toISOString().slice(0, 10) : '?';
    const used = record.lastUsedAt ? new Date(record.lastUsedAt * 1000).toISOString().slice(0, 10) : 'never';
    return `${record.name} [${record.id}] created ${created}, last used ${used}`;
}

export function apiTokenIdFromLabel(label: string): string | undefined {
    return /\[([0-9a-f]{8})\]/.exec(label)?.[1];
}
