import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getComponent, isExpectedDisconnectError } from '../scrypted';

interface BackupComponent {
    createBackup(): Promise<Buffer>;
    restore(b: Buffer): Promise<void>;
}

// The exact phrase a caller must pass in `confirm` to arm the destructive path. Bundled
// here (rather than in a description string) so the description and the check can't drift.
const RESTORE_TRIPWIRE = 'RESTORE FROM BACKUP';

function timestampSlug() {
    return new Date().toISOString().replace(/[:.]/g, '-');
}

// Strict base64 decode. `Buffer.from(s, 'base64')` is famously lenient — it silently drops
// whitespace, ignores non-base64 chars after the first invalid one, and accepts unpadded
// input. For a destructive `restore_backup` call we want the inverse: refuse early if the
// input doesn't match RFC 4648 standard base64 verbatim (with padding), so we never stage
// silently-truncated bytes and call `backup.restore()` on them.
function strictBase64Decode(input: string): Buffer {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
        throw new Error('backupBase64 contains characters that are not standard base64 (RFC 4648)');
    }
    if (input.length === 0 || input.length % 4 !== 0) {
        throw new Error('backupBase64 length must be a positive multiple of 4 (with padding)');
    }
    const buf = Buffer.from(input, 'base64');
    // Round-trip: re-encode and compare. Catches edge cases like trailing junk past padding
    // that the regex above lets through (e.g. "AAAA====" passes the char check but won't
    // round-trip).
    if (buf.toString('base64') !== input) {
        throw new Error('backupBase64 did not round-trip cleanly; the input is malformed');
    }
    return buf;
}

export const createBackupInput = z.object({});

export async function createBackup() {
    const backup = await getComponent<BackupComponent>('backup');
    const buf = await backup.createBackup();
    // RPC peer hands us back a Buffer or Uint8Array masquerading as one. Coerce so the
    // downstream Buffer.toString('base64') sees a real Buffer.
    const data = Buffer.isBuffer(buf) ? buf : Buffer.from(buf as unknown as ArrayBufferLike);

    const sha256 = createHash('sha256').update(data).digest('hex');
    const summary = { bytes: data.length, sha256 };

    // Synthetic URI — we no longer stage a tmp file on the Scrypted host, so there's no
    // filesystem path to reference. The agent saves the inline blob wherever it wants on
    // its own box. Keep the URI distinct per snapshot so clients can't confuse two
    // backups taken in the same session.
    const uri = `scrypted:backup/${timestampSlug()}.zip`;

    // Returned shape is consumed by the wrap() raw-content path in main.ts. The first block
    // is a JSON summary (size + sha256 for verification); the second carries the actual ZIP
    // bytes inline as a base64 blob.
    return {
        content: [
            { type: 'text' as const, text: JSON.stringify(summary, null, 2) },
            {
                type: 'resource' as const,
                resource: {
                    uri,
                    mimeType: 'application/zip',
                    blob: data.toString('base64'),
                },
            },
        ],
    };
}

export const restoreBackupInput = z.object({
    backupBase64: z
        .string()
        .min(1)
        .describe(
            'The backup ZIP, base64-encoded. The MCP host decodes it in memory and hands the bytes directly to Scrypted to restore — no tmp file is staged on the host.',
        ),
    confirm: z
        .string()
        .describe(
            `Confirmation tripwire. Must be the exact string: "${RESTORE_TRIPWIRE}". Independent of the user's elicitation response.`,
        ),
});

// `restoreBackup` needs the live McpServer to issue an elicitation request mid-call. Returned
// as a factory so the closure captures the server without leaking it as a global.
export function makeRestoreBackupHandler(server: McpServer) {
    return async function restoreBackup(args: z.infer<typeof restoreBackupInput>) {
        if (args.confirm !== RESTORE_TRIPWIRE)
            throw new Error(
                `confirm must equal "${RESTORE_TRIPWIRE}" verbatim. The agent must surface this confirmation to the user before calling restore_backup.`,
            );

        // Decode in memory and hold the buffer for the rest of the handler. We deliberately
        // do NOT stage a tmp file on the Scrypted host — the bytes already came from the
        // client, so re-uploading on a retry is cheap, and this avoids accumulating large
        // ZIPs in os.tmpdir() across failed/cancelled restore attempts.
        const data = strictBase64Decode(args.backupBase64);
        if (data.length === 0) throw new Error('backupBase64 decoded to zero bytes');
        const sha256 = createHash('sha256').update(data).digest('hex');

        // Elicitation is the real lock: the server pauses and asks the client to put a
        // confirmation in front of the user. If the client doesn't advertise the elicitation
        // capability we refuse to proceed — without elicitation we can't prove a human ever
        // saw the prompt. Better to fail loud than restore behind the user's back.
        const caps = server.server.getClientCapabilities();
        if (!caps?.elicitation) {
            throw new Error(
                `restore_backup requires a client that supports MCP elicitation; this client did not advertise the capability. Re-invoke with an elicitation-capable client (decoded payload was ${data.length} bytes, sha256=${sha256}).`,
            );
        }

        const elicitation = await server.server.elicitInput({
            message: [
                `About to restore Scrypted from a ${data.length}-byte ZIP (sha256=${sha256}).`,
                'This will kill the running Scrypted server, wipe the existing database and all installed plugin files,',
                'then extract the backup and restart. Plugins will be reinstalled from npm on first boot.',
                'Choose RESTORE to proceed or CANCEL to abort.',
            ].join(' '),
            requestedSchema: {
                type: 'object',
                properties: {
                    confirm: {
                        type: 'string',
                        title: 'Confirm restore',
                        description: 'Choose RESTORE to proceed or CANCEL to abort.',
                        enum: ['RESTORE', 'CANCEL'],
                    },
                },
                required: ['confirm'],
            },
        });

        if (elicitation.action !== 'accept') {
            return { restored: false, reason: `user ${elicitation.action}ed` };
        }
        const elicitedConfirm = elicitation.content?.confirm;
        if (elicitedConfirm !== 'RESTORE') {
            return { restored: false, reason: `user did not confirm (got: ${String(elicitedConfirm)})` };
        }

        const backup = await getComponent<BackupComponent>('backup');
        try {
            await backup.restore(data);
        } catch (e) {
            // Server-side restore() calls runtime.kill() then schedules a restart, so the
            // RPC connection drops before the call resolves. Treat *that* disconnect as
            // success — but real failures (corrupt ZIP rejected by the restore validator,
            // permission errors, etc.) must propagate so we don't silently report a
            // successful restore that never happened. The buffer is gone after this returns;
            // a retry requires re-uploading the same base64.
            if (!isExpectedDisconnectError(e)) throw e;
        }
        return { restored: true, bytes: data.length, sha256 };
    };
}
