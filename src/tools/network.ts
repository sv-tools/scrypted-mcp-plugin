import { z } from 'zod';
import { getComponent } from '../scrypted.js';

interface AddressesComponent {
    getLocalAddresses(raw?: boolean): Promise<string[] | undefined>;
    setLocalAddresses(addresses: string[]): Promise<void>;
    getExternalAddresses(id: string): Promise<string[]>;
    setExternalAddresses(id: string, addresses: string[]): Promise<void>;
}

interface CorsComponent {
    getCORS(id: string): Promise<string[]>;
    setCORS(id: string, origins: string[]): Promise<void>;
}

export const getLocalAddressesInput = z.object({
    raw: z
        .boolean()
        .optional()
        .describe('If true, returns the raw configured strings (interface names or addresses) without OS resolution.'),
});

export async function getLocalAddresses(args: z.infer<typeof getLocalAddressesInput>) {
    const addresses = await getComponent<AddressesComponent>('addresses');
    const list = await addresses.getLocalAddresses(args.raw);
    return { addresses: list ?? [] };
}

export const setLocalAddressesInput = z.object({
    addresses: z
        .array(z.string())
        .describe(
            'Replacement list of local addresses or network interface names (e.g. ["en0", "192.168.1.10"]). Stored verbatim.',
        ),
});

export async function setLocalAddresses(args: z.infer<typeof setLocalAddressesInput>) {
    const addresses = await getComponent<AddressesComponent>('addresses');
    await addresses.setLocalAddresses(args.addresses);
    return { set: args.addresses };
}

export const getExternalAddressesInput = z.object({
    id: z.string().describe('Plugin device id whose external addresses to fetch.'),
});

export async function getExternalAddresses(args: z.infer<typeof getExternalAddressesInput>) {
    const addresses = await getComponent<AddressesComponent>('addresses');
    const list = await addresses.getExternalAddresses(args.id);
    return { addresses: list ?? [] };
}

export const setExternalAddressesInput = z.object({
    id: z.string().describe('Plugin device id.'),
    addresses: z
        .array(z.string())
        .describe('Replacement list of external (publicly reachable) URLs/addresses for this plugin.'),
});

export async function setExternalAddresses(args: z.infer<typeof setExternalAddressesInput>) {
    const addresses = await getComponent<AddressesComponent>('addresses');
    await addresses.setExternalAddresses(args.id, args.addresses);
    return { set: args.addresses };
}

export const getCorsInput = z.object({
    id: z.string().describe('Plugin/endpoint id whose CORS allowlist to fetch.'),
});

export async function getCors(args: z.infer<typeof getCorsInput>) {
    const cors = await getComponent<CorsComponent>('cors');
    const origins = await cors.getCORS(args.id);
    return { origins: origins ?? [] };
}

export const setCorsInput = z.object({
    id: z.string().describe('Plugin/endpoint id.'),
    origins: z.array(z.string()).describe('Replacement list of allowed CORS origins for this endpoint.'),
});

export async function setCors(args: z.infer<typeof setCorsInput>) {
    const cors = await getComponent<CorsComponent>('cors');
    await cors.setCORS(args.id, args.origins);
    return { set: args.origins };
}
