import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

// Persisted credentials live here. Mode 0600 so other users on a shared host can't read them.
// Env vars override this file when set, so power users / CI can still configure inline.
const CONFIG_DIR = join(homedir(), '.scrypted-mcp');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

export interface Config {
    baseUrl: string;
    username: string;
    password: string;
}

export function loadConfig(): Config {
    const envUrl = process.env.SCRYPTED_URL;
    const envUser = process.env.SCRYPTED_USERNAME;
    const envPass = process.env.SCRYPTED_PASSWORD;
    if (envUrl && envUser && envPass) return { baseUrl: envUrl, username: envUser, password: envPass };

    if (!existsSync(CONFIG_PATH)) {
        throw new Error(
            `Scrypted credentials not configured. Run 'scrypted-mcp setup' to create ${CONFIG_PATH}, ` +
                `or set SCRYPTED_URL, SCRYPTED_USERNAME, SCRYPTED_PASSWORD env vars.`,
        );
    }
    const raw = readFileSync(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<Config>;
    if (!parsed.baseUrl || !parsed.username || !parsed.password)
        throw new Error(`${CONFIG_PATH} is missing baseUrl/username/password — re-run 'scrypted-mcp setup'.`);
    // Env vars partially override the saved config, so a single field can be tweaked without
    // rewriting the whole file (e.g. SCRYPTED_URL=… for a one-off remote test).
    return {
        baseUrl: envUrl ?? parsed.baseUrl,
        username: envUser ?? parsed.username,
        password: envPass ?? parsed.password,
    };
}

export function saveConfig(cfg: Config) {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    chmodSync(CONFIG_PATH, 0o600);
    return CONFIG_PATH;
}

export function getConfigPath() {
    return CONFIG_PATH;
}

// Resolve a partial dirname for display (replace $HOME with ~). Purely cosmetic.
export function displayPath(p: string) {
    const home = homedir();
    return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

export { dirname };
