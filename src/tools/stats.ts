import { readFileSync, readdirSync } from 'node:fs';
import os from 'node:os';
import { z } from 'zod';
import { redactSecrets } from '../redact';
import { getComponent, systemManager } from '../scrypted';

interface PluginComponent {
    getPluginInfo(pluginId: string): Promise<{ pid?: number } | undefined>;
}

// USER_HZ. The kernel reports /proc/<pid>/stat times in these ticks, and it has been 100 on
// every mainstream Linux ABI for decades. Node can't call sysconf(_SC_CLK_TCK), and shelling
// out to getconf just to learn "100" isn't worth a dependency on the image having it.
const CLK_TCK = 100;

// Plugin child command lines carry camera URLs (rtsp://user:pass@host/...), so they go through
// the same redaction as consoles, and are clipped so one ffmpeg filter graph can't flood the
// response.
const MAX_COMMAND_CHARS = 300;

interface ProcSample {
    pid: number;
    ppid: number;
    comm: string;
    ticks: number;
    threads: number;
    startTicks: number;
}

// One read of every /proc/<pid>/stat. Processes come and go during the scan, so a vanished pid
// is skipped rather than failing the whole snapshot.
function readProcTable(): Map<number, ProcSample> {
    const table = new Map<number, ProcSample>();
    for (const entry of readdirSync('/proc')) {
        if (!/^\d+$/.test(entry)) continue;
        try {
            const raw = readFileSync(`/proc/${entry}/stat`, 'utf8');
            // comm is parenthesized and may itself contain spaces or ')', so split after the
            // last ')'. The remainder starts at field 3 (state).
            const close = raw.lastIndexOf(')');
            const comm = raw.slice(raw.indexOf('(') + 1, close);
            const f = raw
                .slice(close + 2)
                .trim()
                .split(/\s+/);
            table.set(Number(entry), {
                pid: Number(entry),
                ppid: Number(f[1]),
                comm,
                ticks: Number(f[11]) + Number(f[12]), // utime + stime
                threads: Number(f[17]),
                startTicks: Number(f[19]),
            });
        } catch {}
    }
    return table;
}

// VmRSS / VmHWM from /proc/<pid>/status, in kB. Undefined for kernel threads and vanished pids.
function readMemory(pid: number): { rssKb?: number; peakRssKb?: number } {
    try {
        const status = readFileSync(`/proc/${pid}/status`, 'utf8');
        const kb = (key: string) => {
            const m = status.match(new RegExp(`^${key}:\\s+(\\d+)\\s+kB`, 'm'));
            return m ? Number(m[1]) : undefined;
        };
        return { rssKb: kb('VmRSS'), peakRssKb: kb('VmHWM') };
    } catch {
        return {};
    }
}

function readCommand(pid: number, fallback: string): string {
    try {
        const cmd = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ');
        const redacted = redactSecrets(cmd || fallback);
        return redacted.length > MAX_COMMAND_CHARS ? `${redacted.slice(0, MAX_COMMAND_CHARS)}…` : redacted;
    } catch {
        return fallback;
    }
}

function readFirst(...paths: string[]): string | undefined {
    for (const p of paths) {
        try {
            return readFileSync(p, 'utf8').trim();
        } catch {}
    }
    return undefined;
}

const mb = (kb: number | undefined) => (kb === undefined ? undefined : Math.round(kb / 102.4) / 10);
const round1 = (n: number) => Math.round(n * 10) / 10;

// Container-wide numbers so per-plugin figures have a denominator. cgroup v2 first, v1 second;
// "max" (v2) or a near-2^63 value (v1) means no limit.
function readContainer() {
    const bytes = (v: string | undefined) => {
        if (!v || v === 'max') return undefined;
        const n = Number(v);
        return Number.isFinite(n) && n < 2 ** 60 ? n : undefined;
    };
    const used = bytes(readFirst('/sys/fs/cgroup/memory.current', '/sys/fs/cgroup/memory/memory.usage_in_bytes'));
    const limit = bytes(readFirst('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes'));
    let cpuLimit: number | undefined;
    const cpuMax = readFirst('/sys/fs/cgroup/cpu.max');
    if (cpuMax) {
        const [quota, period] = cpuMax.split(/\s+/);
        if (quota !== 'max' && Number(period) > 0) cpuLimit = round1(Number(quota) / Number(period));
    }
    return {
        cpuCores: os.cpus().length,
        cpuLimitCores: cpuLimit,
        loadAverage: os.loadavg().map(n => Math.round(n * 100) / 100),
        memoryUsedMB: used === undefined ? undefined : mb(used / 1024),
        memoryLimitMB: limit === undefined ? undefined : mb(limit / 1024),
        hostMemoryTotalMB: mb(os.totalmem() / 1024),
        hostMemoryFreeMB: mb(os.freemem() / 1024),
    };
}

export const getPluginStatsInput = z.object({
    pluginId: z
        .string()
        .optional()
        .describe('npm package id to report on, e.g. "scrypted-kasa". Omit for every running plugin.'),
    sampleMs: z
        .number()
        .int()
        .min(200)
        .max(5000)
        .optional()
        .describe('CPU sampling window in milliseconds (default 1000). CPU % is the average over this window.'),
    sortBy: z
        .enum(['memory', 'cpu'])
        .optional()
        .describe('Order plugins by total memory or total CPU, highest first (default memory).'),
});

export async function getPluginStats(args: z.infer<typeof getPluginStatsInput>) {
    if (process.platform !== 'linux') {
        throw new Error(`get_plugin_stats reads Linux /proc and is unavailable on ${process.platform}`);
    }
    const sampleMs = args.sampleMs ?? 1000;

    let pluginIds: string[];
    if (args.pluginId) {
        pluginIds = [args.pluginId];
    } else {
        const state = systemManager.getSystemState();
        pluginIds = [
            ...new Set(
                Object.values(state)
                    .map((d: any) => d?.pluginId?.value as string | undefined)
                    .filter((id): id is string => !!id),
            ),
        ];
    }

    const plugins = await getComponent<PluginComponent>('plugins');
    const pids = await Promise.all(
        pluginIds.map(async id => {
            try {
                return { pluginId: id, pid: (await plugins.getPluginInfo(id))?.pid };
            } catch {
                return { pluginId: id, pid: undefined };
            }
        }),
    );

    const before = readProcTable();
    const t0 = process.hrtime.bigint();
    await new Promise(resolve => setTimeout(resolve, sampleMs));
    const after = readProcTable();
    const elapsedSec = Number(process.hrtime.bigint() - t0) / 1e9;
    const uptimeSec = Number(readFirst('/proc/uptime')?.split(/\s+/)[0] ?? 0);

    const children = new Map<number, number[]>();
    for (const p of after.values()) {
        const list = children.get(p.ppid);
        if (list) list.push(p.pid);
        else children.set(p.ppid, [p.pid]);
    }
    const pluginPids = new Set(pids.map(p => p.pid).filter((p): p is number => p !== undefined));

    const describe = (pid: number) => {
        const now = after.get(pid)!;
        const prev = before.get(pid);
        // A pid absent from the first snapshot started inside the window; measure from zero.
        const cpu = ((now.ticks - (prev?.ticks ?? 0)) / CLK_TCK / elapsedSec) * 100;
        const mem = readMemory(pid);
        return {
            pid,
            cpuPercent: round1(cpu),
            rssMB: mb(mem.rssKb),
            peakRssMB: mb(mem.peakRssKb),
            threads: now.threads,
            uptimeSec: Math.max(0, Math.round(uptimeSec - now.startTicks / CLK_TCK)),
        };
    };

    const results = pids.map(({ pluginId, pid }) => {
        // A pid that isn't in our /proc either isn't running or lives on a cluster worker.
        if (pid === undefined || !after.has(pid)) {
            return { pluginId, running: false as const, pid };
        }
        const self = describe(pid);
        const descendants: Array<ReturnType<typeof describe> & { command: string }> = [];
        const stack = [...(children.get(pid) ?? [])];
        while (stack.length) {
            const c = stack.pop()!;
            // Never fold another plugin's host into this one's totals.
            if (pluginPids.has(c)) continue;
            descendants.push({ ...describe(c), command: readCommand(c, after.get(c)!.comm) });
            stack.push(...(children.get(c) ?? []));
        }
        descendants.sort((a, b) => (b.rssMB ?? 0) - (a.rssMB ?? 0));
        return {
            pluginId,
            running: true as const,
            ...self,
            children: descendants,
            totalCpuPercent: round1(self.cpuPercent + descendants.reduce((s, d) => s + d.cpuPercent, 0)),
            totalRssMB: round1((self.rssMB ?? 0) + descendants.reduce((s, d) => s + (d.rssMB ?? 0), 0)),
        };
    });

    const key = args.sortBy === 'cpu' ? 'totalCpuPercent' : 'totalRssMB';
    results.sort((a, b) => ((b as any)[key] ?? -1) - ((a as any)[key] ?? -1));

    // Our own parent is the Scrypted server process that forks every plugin. Report it on its
    // own (no descendants) so its share isn't double-counted with the plugins.
    const server = after.has(process.ppid) ? describe(process.ppid) : undefined;

    return {
        sampleMs,
        note: 'cpuPercent is per core (100 = one full core). RSS sums over-count memory shared between processes.',
        container: readContainer(),
        server,
        plugins: results,
    };
}
