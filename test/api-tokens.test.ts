import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { API_TOKEN_NAME_MAX_LEN, API_TOKEN_PREFIX, ApiTokenStore, isApiTokenFormat } from '../src/api-tokens';
import { MemoryStorage, nullConsole } from './helpers/mock-scrypted';

describe('ApiTokenStore', () => {
    it('creates, hashes, verifies, lists, and revokes tokens without storing plaintext', () => {
        const storage = new MemoryStorage();
        const store = new ApiTokenStore(storage, nullConsole);

        const { token, record } = store.create('  laptop  ');
        assert.ok(token.startsWith(API_TOKEN_PREFIX));
        assert.equal(isApiTokenFormat(token), true);
        assert.equal(isApiTokenFormat('eyJhbGciOiJFUzI1NiJ9.x.y'), false);
        assert.equal(record.name, 'laptop');

        for (const k of storage.keys()) {
            assert.ok(!k.includes(token));
            assert.ok(!(storage.getItem(k) ?? '').includes(token));
        }

        const verified = store.verify(token);
        assert.equal(verified?.id, record.id);
        assert.equal(verified?.name, 'laptop');
        assert.equal(typeof verified?.lastUsedAt, 'number');

        assert.equal(store.list().length, 1);
        assert.equal(store.count(), 1);

        const revoked = store.revoke(record.id);
        assert.equal(revoked?.id, record.id);
        assert.equal(store.verify(token), undefined);
        assert.equal(store.count(), 0);
    });

    it('validates names and handles revokeAll and corrupt records', () => {
        const storage = new MemoryStorage();
        const store = new ApiTokenStore(storage, nullConsole);

        assert.throws(() => store.create('   '), /must not be empty/);
        assert.throws(() => store.create('a'.repeat(API_TOKEN_NAME_MAX_LEN + 1)), /at most/);

        store.create('one');
        store.create('two');
        storage.setItem('apitoken.deadbeef', '{not-json');

        assert.equal(store.list().length, 3);
        assert.equal(store.revokeAll(), 3);
        assert.equal(store.count(), 0);
    });
});
