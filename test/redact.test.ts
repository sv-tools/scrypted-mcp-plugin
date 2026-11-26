import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { redactSecrets } from '../src/redact';

describe('redactSecrets', () => {
    it('redacts URL userinfo including slashes in passwords while preserving npm @scope paths', () => {
        assert.equal(
            redactSecrets('connecting to https://admin:s3cr3t@cam.local:8443/api'),
            'connecting to https://[REDACTED]@cam.local:8443/api',
        );
        assert.equal(
            redactSecrets('rtsp://admin:pa/ss@192.168.1.10:554/stream1'),
            'rtsp://[REDACTED]@192.168.1.10:554/[REDACTED]',
        );
        assert.equal(
            redactSecrets('https://registry.npmjs.org/@scrypted/ring'),
            'https://registry.npmjs.org/@scrypted/ring',
        );
    });

    it('redacts rtsp(s) stream paths (e.g. UniFi Protect tokens)', () => {
        assert.equal(
            redactSecrets('source rtsps://192.168.1.2:7441/AbCdEf123456?enableSrtp'),
            'source rtsps://192.168.1.2:7441/[REDACTED]',
        );
    });

    it('redacts Authorization headers in plain text and JSON payloads', () => {
        assert.equal(redactSecrets('Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.abc.def'), 'Authorization: [REDACTED]');
        assert.equal(redactSecrets('Authorization: Basic dXNlcjpwYXNz'), 'Authorization: [REDACTED]');
        assert.equal(
            redactSecrets('{"Authorization": "Basic dXNlcjpwYXNz", "ok": true}'),
            '{"Authorization": "[REDACTED]", "ok": true}',
        );
        assert.equal(redactSecrets('{"Authorization": "Bearer secret.jwt.token"}'), '{"Authorization": "[REDACTED]"}');
        assert.equal(redactSecrets("authorization='Digest abc123'"), "authorization='[REDACTED]'");
    });

    it('redacts keyword-anchored credentials and bare bearer tokens', () => {
        assert.equal(redactSecrets('token=abc123&foo=bar'), 'token=[REDACTED]&foo=bar');
        assert.equal(redactSecrets('{"password": "my \\"quoted\\" pass"}'), '{"password": "[REDACTED]"}');
        assert.equal(redactSecrets('using Bearer smcp_secret_value here'), 'using Bearer [REDACTED] here');
    });
});
