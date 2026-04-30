import { z } from 'zod';
import { getComponent } from '../scrypted.js';

// ScryptedAlert shape, mirrors server/src/db-types.ts. We surface every field so the LLM can
// triage without a second round-trip.
interface ScryptedAlert {
    _id: string;
    timestamp: number;
    title: string;
    path: string;
    message: string;
}

interface AlertsComponent {
    getAlerts(): Promise<ScryptedAlert[]>;
    removeAlert(alert: ScryptedAlert | { _id: string }): Promise<void>;
    clearAlerts(): Promise<void>;
}

export const listAlertsInput = z.object({
    limit: z
        .number()
        .int()
        .positive()
        .max(2000)
        .optional()
        .describe('Cap on returned alerts. Newest-first ordering. Default 200.'),
});

export async function listAlerts(args: z.infer<typeof listAlertsInput>) {
    const alerts = await getComponent<AlertsComponent>('alerts');
    const all = await alerts.getAlerts();
    all.sort((a, b) => b.timestamp - a.timestamp);
    const limit = args.limit ?? 200;
    return {
        total: all.length,
        returned: Math.min(all.length, limit),
        truncated: all.length > limit,
        alerts: all.slice(0, limit).map(a => ({
            id: a._id,
            ts: new Date(a.timestamp).toISOString(),
            title: a.title,
            path: a.path,
            message: a.message,
        })),
    };
}

export const removeAlertInput = z.object({
    id: z.string().describe('Alert id (the `id` field returned by list_alerts).'),
});

export async function removeAlert(args: z.infer<typeof removeAlertInput>) {
    // Server-side `removeAlert` only reads `alert._id` from its argument, so a stub object
    // with just `_id` is sufficient — saves us round-tripping the full alert from list_alerts.
    const alerts = await getComponent<AlertsComponent>('alerts');
    await alerts.removeAlert({ _id: args.id });
    return { removed: args.id };
}

export const clearAlertsInput = z.object({});

export async function clearAlerts() {
    const alerts = await getComponent<AlertsComponent>('alerts');
    await alerts.clearAlerts();
    return { cleared: true };
}
