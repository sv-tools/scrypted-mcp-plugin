import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateSigningKey, importSigningKeyFromPrivateJwk, sha256Base64Url, signJwt, verifyJwt } from '../src/jwt';

describe('jwt', () => {
    it('signs and verifies ES256 tokens and survives private JWK re-import', async () => {
        const key = await generateSigningKey('kid-1');
        const reimported = await importSigningKeyFromPrivateJwk(JSON.parse(JSON.stringify(key.privateJwk)));
        assert.equal(reimported.kid, 'kid-1');
        assert.equal(reimported.publicJwk.d, undefined);

        const now = Math.floor(Date.now() / 1000);
        const token = await signJwt(key, {
            iss: 'https://host/endpoint/scrypted-mcp/public/',
            aud: 'https://host/endpoint/scrypted-mcp/public/mcp',
            sub: 'admin',
            iat: now,
            exp: now + 60,
            scope: 'mcp',
            client_id: 'c1',
        });

        const payload = await verifyJwt(reimported, token, {
            issuer: 'https://host/endpoint/scrypted-mcp/public/',
            audience: 'https://host/endpoint/scrypted-mcp/public/mcp',
        });
        assert.equal(payload.sub, 'admin');
        assert.equal(payload.client_id, 'c1');
    });

    it('rejects expired, tampered, wrong-issuer, wrong-audience, and bad-alg tokens', async () => {
        const key = await generateSigningKey('kid-2');
        const otherKey = await generateSigningKey('kid-3');
        const now = Math.floor(Date.now() / 1000);
        const opts = { issuer: 'https://a/', audience: 'https://a/mcp' };

        const expired = await signJwt(key, { iss: opts.issuer, aud: opts.audience, exp: now });
        await assert.rejects(() => verifyJwt(key, expired, opts), /expired/);

        const wrongKey = await signJwt(otherKey, { iss: opts.issuer, aud: opts.audience, exp: now + 60 });
        await assert.rejects(() => verifyJwt(key, wrongKey, opts), /signature verification failed/);

        const wrongIss = await signJwt(key, { iss: 'https://b/', aud: opts.audience, exp: now + 60 });
        await assert.rejects(() => verifyJwt(key, wrongIss, opts), /iss mismatch/);

        const wrongAud = await signJwt(key, { iss: opts.issuer, aud: 'https://a/other', exp: now + 60 });
        await assert.rejects(() => verifyJwt(key, wrongAud, opts), /aud mismatch/);

        const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
        const body = Buffer.from(JSON.stringify({ iss: opts.issuer, aud: opts.audience, exp: now + 60 })).toString(
            'base64url',
        );
        await assert.rejects(() => verifyJwt(key, `${noneHeader}.${body}.sig`, opts), /unsupported alg/);

        const nullHeader = Buffer.from('null').toString('base64url');
        await assert.rejects(() => verifyJwt(key, `${nullHeader}.${body}.sig`, opts), /unsupported alg/);
    });

    it('computes RFC 7636 PKCE S256 test vector', async () => {
        const challenge = await sha256Base64Url('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        assert.equal(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    });
});
