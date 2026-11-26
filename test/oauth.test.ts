import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { HttpRequest, HttpResponse } from '@scrypted/sdk';
import { sha256Base64Url } from '../src/jwt';
import { DEFAULT_ACCESS_TOKEN_TTL_SEC, DEFAULT_REFRESH_TOKEN_TTL_SEC, OAuthService } from '../src/oauth';
import { MemoryStorage, nullConsole } from './helpers/mock-scrypted';

interface CapturedResponse {
    code: number;
    headers: Record<string, string>;
    body: string;
}

function makeRes(): { res: HttpResponse; captured: () => CapturedResponse } {
    let result: CapturedResponse | undefined;
    const res = {
        send(body: string | Buffer, opts?: { code?: number; headers?: Record<string, string> }) {
            result = {
                code: opts?.code ?? 200,
                headers: opts?.headers ?? {},
                body: Buffer.isBuffer(body) ? body.toString('utf8') : String(body),
            };
        },
    } as unknown as HttpResponse;
    return {
        res,
        captured: () => {
            if (!result) throw new Error('no response sent');
            return result;
        },
    };
}

function makeService(maxClients = 10) {
    const storage = new MemoryStorage();
    const service = new OAuthService({
        storage,
        console: nullConsole,
        getMaxClients: () => maxClients,
        getAccessTokenTtlSec: () => DEFAULT_ACCESS_TOKEN_TTL_SEC,
        getRefreshTokenTtlSec: () => DEFAULT_REFRESH_TOKEN_TTL_SEC,
    });
    return { service, storage };
}

function baseReq(overrides: Partial<HttpRequest>): HttpRequest {
    return {
        method: 'GET',
        rootPath: '/endpoint/scrypted-mcp/public',
        isPublicEndpoint: true,
        headers: { host: 'scrypted.local:10443' },
        ...overrides,
    };
}

describe('OAuthService', () => {
    it('accepts loopback redirect URIs including IPv6 [::1] and rejects non-loopback or oversized payloads', async () => {
        const { service } = makeService();

        for (const uri of ['http://localhost:8123/cb', 'http://127.0.0.1:8123/cb', 'http://[::1]:8123/cb']) {
            const { res, captured } = makeRes();
            await service.handle(
                baseReq({
                    method: 'POST',
                    url: '/endpoint/scrypted-mcp/public/register',
                    body: JSON.stringify({ redirect_uris: [uri], client_name: 'test' }),
                }),
                res,
            );
            assert.equal(captured().code, 201, `expected 201 for ${uri}, got ${captured().body}`);
        }

        for (const bad of [
            { redirect_uris: ['https://evil.example/cb'] },
            { redirect_uris: ['https://localhost:8123/cb'] },
            { redirect_uris: ['http://localhost:8123/cb'], client_name: 'x'.repeat(200) },
            { redirect_uris: ['http://localhost:8123/cb'], scope: 'x'.repeat(300) },
            { redirect_uris: Array.from({ length: 20 }, (_, i) => `http://localhost:${8000 + i}/cb`) },
        ]) {
            const { res, captured } = makeRes();
            await service.handle(
                baseReq({
                    method: 'POST',
                    url: '/endpoint/scrypted-mcp/public/register',
                    body: JSON.stringify(bad),
                }),
                res,
            );
            assert.equal(captured().code, 400);
        }
    });

    it('runs full PKCE authorize -> token -> verifyBearer -> refresh rotation -> revokeAll flow', async () => {
        const { service } = makeService();
        const redirectUri = 'http://[::1]:9000/callback';
        const resource = 'https://scrypted.local:10443/endpoint/scrypted-mcp/public/mcp';

        // Register
        const reg = makeRes();
        await service.handle(
            baseReq({
                method: 'POST',
                url: '/endpoint/scrypted-mcp/public/register',
                body: JSON.stringify({ redirect_uris: [redirectUri], client_name: 'claude-code' }),
            }),
            reg.res,
        );
        assert.equal(reg.captured().code, 201);
        const { client_id: clientId } = JSON.parse(reg.captured().body);

        // Unauthenticated /authorize -> 401
        const unauth = makeRes();
        await service.handle(
            baseReq({ url: `/endpoint/scrypted-mcp/public/authorize?client_id=${clientId}` }),
            unauth.res,
        );
        assert.equal(unauth.captured().code, 401);

        // ACL-restricted user -> 403
        const acl = makeRes();
        await service.handle(
            baseReq({
                url: `/endpoint/scrypted-mcp/public/authorize?client_id=${clientId}`,
                username: 'guest',
                aclId: 'acl-1',
            }),
            acl.res,
        );
        assert.equal(acl.captured().code, 403);

        // Admin /authorize with PKCE
        const verifier = 'verifier-0123456789abcdefghijklmnopqrstuvwxyz';
        const challenge = await sha256Base64Url(verifier);
        const authRes = makeRes();
        const authQuery = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state: 'st-1',
            scope: 'mcp',
            resource,
        });
        await service.handle(
            baseReq({
                url: `/endpoint/scrypted-mcp/public/authorize?${authQuery.toString()}`,
                username: 'admin',
            }),
            authRes.res,
        );
        assert.equal(authRes.captured().code, 302);
        const loc = new URL(authRes.captured().headers.Location);
        assert.equal(loc.searchParams.get('state'), 'st-1');
        assert.equal(loc.searchParams.get('iss'), 'https://scrypted.local:10443/endpoint/scrypted-mcp/public/');
        const code = loc.searchParams.get('code')!;
        assert.ok(code);

        // Wrong resource on /token -> 400 invalid_target (without consuming code)
        const badResource = makeRes();
        await service.handle(
            baseReq({
                method: 'POST',
                url: '/endpoint/scrypted-mcp/public/token',
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code,
                    code_verifier: verifier,
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    resource: 'https://other.example/mcp',
                }),
            }),
            badResource.res,
        );
        assert.equal(badResource.captured().code, 400);
        assert.equal(JSON.parse(badResource.captured().body).error, 'invalid_target');

        // Valid /token exchange
        const tokRes = makeRes();
        await service.handle(
            baseReq({
                method: 'POST',
                url: '/endpoint/scrypted-mcp/public/token',
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code,
                    code_verifier: verifier,
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    resource,
                }),
            }),
            tokRes.res,
        );
        assert.equal(tokRes.captured().code, 200);
        const tokens = JSON.parse(tokRes.captured().body);
        assert.ok(tokens.access_token);
        assert.ok(tokens.refresh_token);

        // Verify Bearer (including trailing whitespace and uppercase x-forwarded-proto)
        const info = await service.verifyBearer(
            baseReq({
                headers: {
                    host: 'scrypted.local:10443',
                    'x-forwarded-proto': 'HTTPS',
                    authorization: `Bearer ${tokens.access_token}  `,
                },
            }),
        );
        assert.equal(info?.clientId, clientId);
        assert.equal(info?.extra?.sub, 'admin');

        // Refresh token rotation
        const ref1 = makeRes();
        await service.handle(
            baseReq({
                method: 'POST',
                url: '/endpoint/scrypted-mcp/public/token',
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokens.refresh_token,
                    client_id: clientId,
                }),
            }),
            ref1.res,
        );
        assert.equal(ref1.captured().code, 200);
        const tokens2 = JSON.parse(ref1.captured().body);
        assert.notEqual(tokens2.refresh_token, tokens.refresh_token);

        // Replay of rotated RT -> 400 invalid_grant
        const replay = makeRes();
        await service.handle(
            baseReq({
                method: 'POST',
                url: '/endpoint/scrypted-mcp/public/token',
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokens.refresh_token,
                    client_id: clientId,
                }),
            }),
            replay.res,
        );
        assert.equal(replay.captured().code, 400);
        assert.equal(JSON.parse(replay.captured().body).error, 'invalid_grant');

        // Revoke all invalidates access token, client, and RT
        const counts = await service.revokeAll();
        assert.equal(counts.clients, 1);
        assert.equal(counts.refreshTokens, 1);
        const afterRevoke = await service.verifyBearer(
            baseReq({ headers: { host: 'scrypted.local:10443', authorization: `Bearer ${tokens2.access_token}` } }),
        );
        assert.equal(afterRevoke, undefined);
    });

    it('sanitizes invalid x-forwarded-proto values when building metadata', async () => {
        const { service } = makeService();
        const { res, captured } = makeRes();
        await service.handle(
            baseReq({
                url: '/endpoint/scrypted-mcp/public/.well-known/oauth-protected-resource',
                headers: { host: 'scrypted.local:11080', 'x-forwarded-proto': 'javascript' },
            }),
            res,
        );
        assert.equal(captured().code, 200);
        const doc = JSON.parse(captured().body);
        assert.equal(doc.resource, 'http://scrypted.local:11080/endpoint/scrypted-mcp/public/mcp');
    });
});
