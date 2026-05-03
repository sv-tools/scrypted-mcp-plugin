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
