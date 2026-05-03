import { z } from 'zod';
import { getComponent } from '../scrypted';

// The Logger component returns the entire in-memory log buffer (Scrypted purges entries
// older than 48h). Each entry has timestamp, level, title (component path), and message.
interface LogEntry {
    timestamp: number;
    level: string;
    title: string;
    message: string;
}

interface LoggerComponent {
    getLogs(): Promise<LogEntry[]>;
    clearLogs?(): Promise<void>;
}

export const getLogsInput = z.object({
    component: z
        .string()
        .optional()
        .describe(
            'Filter by component path / plugin id (substring match against the entry title). Omit to get all logs.',
        ),
    sinceMs: z
        .number()
        .optional()
        .describe('Unix epoch ms; only return entries with timestamp >= this. Omit for all retained logs (~48h).'),
    level: z
        .enum(['e', 'w', 'i', 'd', 'v', 'a'])
        .optional()
        .describe('Filter by level: e=error, w=warn, i=info, d=debug, v=verbose, a=alert.'),
    limit: z
        .number()
        .int()
        .positive()
        .max(2000)
        .optional()
        .describe('Cap on returned entries. Newest-first ordering. Default 200.'),
});

export async function getLogs(args: z.infer<typeof getLogsInput>) {
    const logger = await getComponent<LoggerComponent>('logger');
    const all = await logger.getLogs();
    let filtered = all;
    if (args.component) {
        const needle = args.component.toLowerCase();
        filtered = filtered.filter(e => e.title?.toLowerCase().includes(needle));
    }
    if (args.sinceMs !== undefined) filtered = filtered.filter(e => e.timestamp >= args.sinceMs!);
    if (args.level) filtered = filtered.filter(e => e.level === args.level);
    // Newest-first so the LLM sees recent context up top within its budget.
    filtered.sort((a, b) => b.timestamp - a.timestamp);
    const limit = args.limit ?? 200;
    const truncated = filtered.length > limit;
    return {
        total: all.length,
        matched: filtered.length,
        returned: Math.min(filtered.length, limit),
        truncated,
        entries: filtered.slice(0, limit).map(e => ({
            ts: new Date(e.timestamp).toISOString(),
            level: e.level,
            title: e.title,
            message: e.message,
        })),
    };
}

export const clearLogsInput = z.object({});

export async function clearLogs() {
    const logger = await getComponent<LoggerComponent>('logger');
    if (typeof logger.clearLogs !== 'function')
        throw new Error('logger component does not expose clearLogs on this Scrypted version');
    await logger.clearLogs();
    return { cleared: true };
}
