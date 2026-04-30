import { z } from 'zod';
import { getComponent } from '../scrypted.js';

interface InfoComponent {
    getVersion(): Promise<string>;
    getScryptedEnv(): Promise<Record<string, string | undefined>>;
}

interface ServiceControlComponent {
    restart(): Promise<void>;
    update(): Promise<void>;
    getUpdateAvailable?(): Promise<string>;
}

interface EnvControlComponent {
    getDotEnv(): Promise<string>;
    setDotEnv(env: string): Promise<void>;
}

export const getServerInfoInput = z.object({});

export async function getServerInfo() {
    // Combine version + SCRYPTED_* env into one snapshot — saves a round-trip when the LLM
    // wants to know "what server am I talking to". `getUpdateAvailable` is intentionally
    // skipped here: the upstream impl throws "not implemented" by design (updates ride
    // through Docker/npm out-of-band), so calling it just produces noise.
    const info = await getComponent<InfoComponent>('info');
    const [version, env] = await Promise.all([info.getVersion(), info.getScryptedEnv()]);
    return { version, env };
}

export const restartServerInput = z.object({});

export async function restartServer() {
    // restart() calls process.exit() server-side; the RPC peer dies before the call resolves.
    // We swallow that disconnect so the tool reports success rather than a transport error.
    const svc = await getComponent<ServiceControlComponent>('service-control');
    try {
        await svc.restart();
    } catch {
        // Connection drops are expected — that's the restart happening.
    }
    return { restarting: true };
}

export const updateServerInput = z.object({});

export async function updateServer() {
    // Triggers SCRYPTED_WEBHOOK_UPDATE if set, otherwise writes `.update` and restarts.
    // Same disconnect handling as restartServer.
    const svc = await getComponent<ServiceControlComponent>('service-control');
    try {
        await svc.update();
    } catch {
        // Same: server-initiated restart kills the RPC connection.
    }
    return { updating: true };
}

export const getDotEnvInput = z.object({});

export async function getDotEnv() {
    const env = await getComponent<EnvControlComponent>('env-control');
    try {
        const content = await env.getDotEnv();
        return { content };
    } catch (e: any) {
        // ENOENT is normal — no .env file has been written yet. Surface it as empty content
        // rather than an error so the LLM can decide whether to seed one with set_dotenv.
        if (e?.code === 'ENOENT') return { content: '' };
        throw e;
    }
}

export const setDotEnvInput = z.object({
    content: z
        .string()
        .describe(
            'Full replacement contents of the Scrypted .env file. Server-side this is written verbatim — be sure to include all existing keys you want to keep.',
        ),
});

export async function setDotEnv(args: z.infer<typeof setDotEnvInput>) {
    const env = await getComponent<EnvControlComponent>('env-control');
    await env.setDotEnv(args.content);
    return { written: true, bytes: Buffer.byteLength(args.content, 'utf8') };
}
