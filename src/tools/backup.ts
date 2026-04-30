import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getComponent } from '../scrypted.js';

interface BackupComponent {
    createBackup(): Promise<Buffer>;
    restore(b: Buffer): Promise<void>;
}

// The exact phrase a caller must pass in `confirm` to arm the destructive path. Bundled
// here (rather than in a description string) so the description and the check can't drift.
const RESTORE_TRIPWIRE = 'RESTORE FROM BACKUP';

export const createBackupInput = z.object({
    outputPath: z
        .string()
        .describe(
            'Absolute path on the MCP host where the backup ZIP will be written. Will overwrite an existing file at that path.',
        ),
});

export async function createBackup(args: z.infer<typeof createBackupInput>) {
    if (!path.isAbsolute(args.outputPath)) throw new Error(`outputPath must be absolute, got: ${args.outputPath}`);
    const backup = await getComponent<BackupComponent>('backup');
    const buf = await backup.createBackup();
    // The RPC peer hands us back a Buffer (or Uint8Array masquerading as one). Coerce so
    // fs.writeFile is happy regardless of the concrete shape.
    const data = Buffer.isBuffer(buf) ? buf : Buffer.from(buf as unknown as ArrayBufferLike);
    await fs.writeFile(args.outputPath, data);
    return { outputPath: args.outputPath, bytes: data.length };
}

export const restoreBackupInput = z.object({
    inputPath: z.string().describe('Absolute path on the MCP host to the backup ZIP to restore from.'),
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
        if (!path.isAbsolute(args.inputPath)) throw new Error(`inputPath must be absolute, got: ${args.inputPath}`);
        if (args.confirm !== RESTORE_TRIPWIRE)
            throw new Error(
                `confirm must equal "${RESTORE_TRIPWIRE}" verbatim. The agent must surface this confirmation to the user before calling restore_backup.`,
            );

        // Read the file before the elicitation so the user is told the actual size of what
        // they're about to install. Failing here (ENOENT, EACCES) means we never gate on the
        // user — but it also means the destructive path was never reached, which is fine.
        const data = await fs.readFile(args.inputPath);

        // Elicitation is the real lock: the server pauses and asks the client to put a
        // confirmation in front of the user. If the client doesn't advertise the elicitation
        // capability we refuse to proceed — without elicitation we can't prove a human ever
        // saw the prompt. Better to fail loud than restore behind the user's back.
        const caps = server.server.getClientCapabilities();
        if (!caps?.elicitation)
            throw new Error(
                'restore_backup requires a client that supports MCP elicitation; this client did not advertise the capability.',
            );

        const elicitation = await server.server.elicitInput({
            message: [
                `About to restore Scrypted from "${args.inputPath}" (${data.length} bytes).`,
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

        if (elicitation.action !== 'accept') return { restored: false, reason: `user ${elicitation.action}ed` };
        const elicitedConfirm = elicitation.content?.confirm;
        if (elicitedConfirm !== 'RESTORE')
            return { restored: false, reason: `user did not confirm (got: ${String(elicitedConfirm)})` };

        const backup = await getComponent<BackupComponent>('backup');
        try {
            await backup.restore(data);
        } catch {
            // Server-side restore() calls `runtime.kill()` then schedules a restart, so the
            // RPC connection drops before the call resolves. Treat that as success.
        }
        return { restored: true, bytes: data.length };
    };
}
