import { sdk } from '@scrypted/sdk';

// Tools used to drive a remote Scrypted server through @scrypted/client. Now we run inside
// the server as a plugin, so the runtime SDK is available directly. This module exists only
// to expose the bits the tools reach for, behind the same names as before, so each tool file
// stays a near-verbatim port.

export { sdk };

export const systemManager = sdk.systemManager;
export const deviceManager = sdk.deviceManager;
export const mediaManager = sdk.mediaManager;
export const endpointManager = sdk.endpointManager;

// Components are runtime-registered services on the Scrypted server (logger, plugins,
// alerts, ...). @scrypted/types doesn't ship narrow types for them, so the generic stays
// loosely typed and each call site asserts the shape it actually uses.
export async function getComponent<T = any>(name: string): Promise<T> {
    return sdk.systemManager.getComponent(name) as Promise<T>;
}

// Some component RPCs (backup.restore, service-control.restart/update) intentionally drop
// the RPC channel before resolving — they call process.exit / runtime.kill server-side.
// Tools that invoke those want to report success when the connection drops as expected, but
// must NOT swallow real validation/permission errors. This heuristic matches on the error
// shapes Node/Scrypted produce for a torn-down RPC peer or socket; anything else falls
// through and propagates.
export function isExpectedDisconnectError(e: unknown): boolean {
    if (!e) return false;
    const err = e as { code?: string; message?: string };
    if (err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ECONNABORTED') return true;
    const msg = String(err.message ?? '');
    return (
        /socket hang up/i.test(msg) ||
        /connection (closed|reset|aborted|terminated)/i.test(msg) ||
        /rpc.*?(closed|killed|disconnect|ended)/i.test(msg) ||
        /peer.*?(closed|killed|ended|disconnect)/i.test(msg) ||
        /not connected/i.test(msg) ||
        /channel closed/i.test(msg) ||
        /connection ended/i.test(msg)
    );
}
