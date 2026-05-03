import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getComponent } from '../scrypted';

interface BackupComponent {
    createBackup(): Promise<Buffer>;
    restore(b: Buffer): Promise<void>;
}

// The exact phrase a caller must pass in `confirm` to arm the destructive path. Bundled
// here (rather than in a description string) so the description and the check can't drift.
const RESTORE_TRIPWIRE = 'RESTORE FROM BACKUP';

// 1 hour. Tmp file lives long enough for a chained MCP tool call (e.g. write_file on the
// agent's local box) to consume it via the path; beyond that we don't want to leak GBs of
// snapshot ZIPs onto the Scrypted host's filesystem.
const TMP_RETENTION_MS = 60 * 60 * 1000;

function timestampSlug() {
    return new Date().toISOString().replace(/[:.]/g, '-');
}

export const createBackupInput = z.object({});

export async function createBackup() {
    const backup = await getComponent<BackupComponent>('backup');
    const buf = await backup.createBackup();
    // RPC peer hands us back a Buffer or Uint8Array masquerading as one. Coerce so the
    // downstream Buffer.toString('base64') and fs.writeFile both see a real Buffer.
    const data = Buffer.isBuffer(buf) ? buf : Buffer.from(buf as unknown as ArrayBufferLike);

    const tmpPath = path.join(os.tmpdir(), `scrypted-backup-${timestampSlug()}.zip`);
    await fs.writeFile(tmpPath, data);

    // Best-effort cleanup. Don't block the tool result on the timer; Node's unref keeps the
    // event loop free, and a missed cleanup just leaves a stale file in /tmp.
    setTimeout(() => {
        fs.rm(tmpPath, { force: true }).catch(() => {});
    }, TMP_RETENTION_MS).unref();

    const sha256 = createHash('sha256').update(data).digest('hex');
    const summary = {
        tmpPath,
        bytes: data.length,
        sha256,
        retentionMs: TMP_RETENTION_MS,
    };

    // Returned shape is consumed by the wrap() raw-content path in main.ts. The first block
    // is a JSON summary so the agent can echo size/path; the second carries the actual ZIP
    // bytes inline as a base64 blob, which the agent saves wherever the user wants.
    return {
        content: [
            { type: 'text' as const, text: JSON.stringify(summary, null, 2) },
            {
                type: 'resource' as const,
                resource: {
                    uri: `file://${tmpPath}`,
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
            'The backup ZIP, base64-encoded. The MCP host decodes this, writes it to a tmp file, then hands the bytes to Scrypted to restore.',
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

        // Decode and stage to tmp before the elicitation prompt so the user is told the
        // actual size of what they're about to install. Failing here (bad base64, ENOSPC)
        // means we never gate on the user — but it also means the destructive path was
        // never reached, which is fine.
        const data = Buffer.from(args.backupBase64, 'base64');
        if (data.length === 0) throw new Error('backupBase64 decoded to zero bytes');

        const tmpPath = path.join(os.tmpdir(), `scrypted-restore-${timestampSlug()}.zip`);
        await fs.writeFile(tmpPath, data);

        // Elicitation is the real lock: the server pauses and asks the client to put a
        // confirmation in front of the user. If the client doesn't advertise the elicitation
        // capability we refuse to proceed — without elicitation we can't prove a human ever
        // saw the prompt. Better to fail loud than restore behind the user's back.
        const caps = server.server.getClientCapabilities();
        if (!caps?.elicitation) {
            // Leave tmp in place so an operator can recover. Surface the path.
            throw new Error(
                `restore_backup requires a client that supports MCP elicitation; this client did not advertise the capability. Staged ZIP left at ${tmpPath}.`,
            );
        }

        const elicitation = await server.server.elicitInput({
            message: [
                `About to restore Scrypted from staged ZIP at "${tmpPath}" (${data.length} bytes).`,
                'This will kill the running Scrypted server, wipe the existing database and all installed plugin files,',
                'then extract the backup and restart. Plugins will be reinstalled from npm on first boot.',
                'Type RESTORE to proceed, or anything else to cancel.',
            ].join(' '),
            requestedSchema: {
                type: 'object',
                properties: {
                    confirm: {
                        type: 'string',
                        title: 'Confirm restore',
                        description: 'Type RESTORE to proceed.',
                        enum: ['RESTORE', 'CANCEL'],
                    },
                },
                required: ['confirm'],
            },
        });

        if (elicitation.action !== 'accept') {
            await fs.rm(tmpPath, { force: true }).catch(() => {});
            return { restored: false, reason: `user ${elicitation.action}ed` };
        }
        const elicitedConfirm = elicitation.content?.confirm;
        if (elicitedConfirm !== 'RESTORE') {
            await fs.rm(tmpPath, { force: true }).catch(() => {});
            return { restored: false, reason: `user did not confirm (got: ${String(elicitedConfirm)})` };
        }

        const backup = await getComponent<BackupComponent>('backup');
        try {
            await backup.restore(data);
        } catch {
            // Server-side restore() calls runtime.kill() then schedules a restart, so the
            // RPC connection drops before the call resolves. Treat that as success — and
            // leave the tmp file in place; the host is restarting and the cleanup wouldn't
            // run anyway.
        }
        return { restored: true, bytes: data.length, tmpPath };
    };
}
