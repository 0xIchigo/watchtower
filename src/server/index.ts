import { timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { stringify } from 'yaml';
import { endpointsFromEnv, loadConfig, loadEnvFile, MISSING_API_KEY, readRawConfig } from '../config.js';
import { fromBrowser, maskSecrets, saveConfig } from '../configFile.js';
import type { Finding } from '../detectors/types.js';
import { discoverMint, discoverProgram, loadMultisig } from '../discover/index.js';
import { ParsedEventsClient } from '../helius/parsedEvents.js';
import { heliusClient } from '../helius/sdk.js';
import { RpcClient } from '../helius/rpc.js';
import { Monitor, type LogLevel } from '../monitor.js';
import { buildReport } from '../report/build.js';
import { renderHtml, type ReportData } from '../report/render.js';
import { createSinks, dispatch } from '../sinks.js';
import { watchedSubjects } from '../targets.js';

export interface ServerOptions {
    host: string;
    port: number;
    /** The default monitor's config. Further monitors live in `monitors/` next to it. */
    configPath: string;
    backfill: boolean;
    /** Required for any non-loopback host unless `readOnly`. */
    password: string | undefined;
    /** Dashboard only: every write endpoint and the setup UI are disabled. */
    readOnly: boolean;
}

interface LogEntry {
    time: number;
    level: LogLevel;
    message: string;
}

/** One monitor: a config file, its running `Monitor` (if any), and what the dashboard shows for it. */
interface Slot {
    id: string;
    configPath: string;
    monitor: Monitor | null;
    configError: string | null;
    report: ReportData | null;
    reportRunning: boolean;
    reportError: string | null;
    /** Stopped from the dashboard, but kept so its state is still shown. */
    paused: boolean;
    lifecycle: Promise<unknown>;
    logs: LogEntry[];
}

const UI_DIR = new URL('../../ui/', import.meta.url);
const LOGO = new URL('../../assets/brand/Helius-Horizontal-Logo.svg', import.meta.url);
const ICON = new URL('../../assets/brand/Helius-Icon.svg', import.meta.url);
const STATIC_TYPES: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
const FEED_LIMIT = 300;
const LOG_LIMIT = 300;
const MAX_BODY_BYTES = 256 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const DEFAULT_ID = 'default';
const DEFAULT_STATE_FILE = '.watchtower/state.json';
const MONITOR_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function assertSafeBinding(options: Pick<ServerOptions, 'host' | 'password' | 'readOnly'>): void {
    if (LOOPBACK_HOSTS.has(options.host) || options.password || options.readOnly) return;
    throw new Error(
        `Refusing to serve on ${options.host} without protection. Set WATCHTOWER_PASSWORD, or WATCHTOWER_READONLY=true for a public status page.`,
    );
}

/** Serves the dashboard and its API, and runs one `Monitor` per config in-process. */
export class WatchtowerServer {
    readonly #options: ServerOptions;
    readonly #monitorsDir: string;
    #slots = new Map<string, Slot>();
    #clients = new Set<ServerResponse>();

    constructor(options: ServerOptions) {
        assertSafeBinding(options);
        this.#options = options;
        this.#monitorsDir = join(dirname(options.configPath), 'monitors');
    }

    async listen(): Promise<{ url: string; close: () => Promise<void> }> {
        const server = createServer((req, res) => {
            this.#handle(req, res).catch((error: Error) => {
                if (!res.headersSent) json(res, req.method === 'POST' ? 400 : 500, { error: error.message });
                else res.end();
            });
        });
        await new Promise<void>((resolveListen, rejectListen) => {
            server.once('error', rejectListen);
            server.listen(this.#options.port, this.#options.host, () => {
                server.off('error', rejectListen);
                resolveListen();
            });
        });
        const address = server.address();
        const port = typeof address === 'object' && address ? address.port : this.#options.port;
        for (const slot of this.#loadSlots()) void this.#serial(slot, () => this.#startMonitor(slot));
        return {
            url: `http://${this.#options.host.includes(':') ? `[${this.#options.host}]` : this.#options.host}:${port}`,
            close: async () => {
                for (const client of this.#clients) client.end();
                await Promise.all([...this.#slots.values()].map((slot) => slot.monitor?.stop()));
                await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
            },
        };
    }

    async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
        const url = new URL(req.url ?? '/', 'http://localhost');
        res.setHeader('content-security-policy', "frame-ancestors 'none'");
        res.setHeader('x-frame-options', 'DENY');
        res.setHeader('x-content-type-options', 'nosniff');
        if (!this.#hostAllowed(req)) return json(res, 421, { error: 'Unexpected Host header' });
        if (!this.#authorized(req)) {
            res.writeHead(401, { 'www-authenticate': 'Basic realm="Watchtower"' });
            return void res.end('Authentication required');
        }
        if (req.method === 'POST') {
            if (this.#options.readOnly) return json(res, 403, { error: 'This Watchtower is read-only' });
            if (!sameOriginJson(req)) return json(res, 415, { error: 'Expected a same-origin application/json request' });
        }

        const route = `${req.method} ${url.pathname}`;
        if (req.method === 'POST' && route !== 'POST /api/discover' && route !== 'POST /api/monitors') {
            const body = (await readJson(req)) as { monitor?: string };
            const slot = this.#slot(body.monitor);
            switch (route) {
                case 'POST /api/pause':
                    return json(res, 200, await this.#serial(slot, () => this.#pause(slot)));
                case 'POST /api/resume':
                case 'POST /api/reload':
                    return json(res, 200, await this.#serial(slot, () => this.#reload(slot)));
                case 'POST /api/config':
                    return json(res, 200, await this.#serial(slot, () => this.#saveConfig(slot, body)));
                case 'POST /api/report':
                    return json(res, 202, this.#refreshReport(slot));
                case 'POST /api/test-alert':
                    return json(res, 200, await this.#testAlert(slot));
                case 'POST /api/monitors/delete':
                    return json(res, 200, await this.#serial(slot, () => this.#deleteMonitor(slot)));
                default:
                    return json(res, 404, { error: 'Not found' });
            }
        }
        switch (route) {
            case 'GET /api/state':
                loadEnvFile();
                return json(res, 200, this.#snapshot(this.#slot(url.searchParams.get('monitor') ?? undefined)));
            case 'GET /api/events':
                return this.#subscribe(res);
            case 'POST /api/discover':
                return json(res, 200, await this.#discover(await readJson(req)));
            case 'POST /api/monitors':
                return json(res, 200, this.#createMonitor(await readJson(req)));
            case 'GET /report.html':
                return this.#reportHtml(this.#slot(url.searchParams.get('monitor') ?? undefined), res);
            case 'GET /brand/helius.svg':
                return sendFile(res, LOGO, 'image/svg+xml');
            case 'GET /brand/helius-icon.svg':
            case 'GET /favicon.ico':
                return sendFile(res, ICON, 'image/svg+xml');
            case 'GET /':
                return sendFile(res, new URL('index.html', UI_DIR), STATIC_TYPES['.html']!);
            default:
                return this.#static(url.pathname, res);
        }
    }

    /** The default config (when it exists, or when nothing else does) plus every `monitors/*.yaml`. */
    #loadSlots(): Slot[] {
        const extra = existsSync(this.#monitorsDir)
            ? readdirSync(this.#monitorsDir)
                  .filter((file) => file.endsWith('.yaml') && MONITOR_ID.test(basename(file, '.yaml')))
                  .sort()
            : [];
        if (existsSync(this.#options.configPath) || extra.length === 0) this.#addSlot(DEFAULT_ID, this.#options.configPath);
        for (const file of extra) this.#addSlot(basename(file, '.yaml'), join(this.#monitorsDir, file));
        return [...this.#slots.values()];
    }

    #addSlot(id: string, configPath: string): Slot {
        const slot: Slot = {
            id,
            configPath,
            monitor: null,
            configError: null,
            report: null,
            reportRunning: false,
            reportError: null,
            paused: false,
            lifecycle: Promise.resolve(),
            logs: [],
        };
        this.#slots.set(id, slot);
        return slot;
    }

    #slot(id: string | undefined): Slot {
        const slot = id ? this.#slots.get(id) : this.#slots.values().next().value;
        if (!slot) throw new Error(id ? `No monitor named ${id}` : 'No monitors');
        return slot;
    }

    /** Starting, stopping, reloading, saving and deleting a monitor run one at a time, so two monitors never share a state file. */
    #serial<T>(slot: Slot, task: () => Promise<T>): Promise<T> {
        const run = slot.lifecycle.then(task, task);
        slot.lifecycle = run.catch(() => undefined);
        return run;
    }

    async #startMonitor(slot: Slot): Promise<void> {
        loadEnvFile();
        slot.configError = null;
        const raw = this.#savedConfig(slot);
        if (!raw || !Array.isArray(raw.programs) || raw.programs.length === 0) {
            this.#log(slot, 'info', 'Not configured yet. Open the Setup tab to add a program.');
            this.#broadcastState(slot);
            return;
        }
        let monitor: Monitor;
        try {
            monitor = new Monitor(loadConfig(slot.configPath), { backfill: this.#options.backfill });
        } catch (error) {
            slot.configError = (error as Error).message;
            this.#log(slot, 'warn', slot.configError);
            this.#broadcastState(slot);
            return;
        }
        slot.monitor = monitor;
        monitor.on('log', (level, message) => this.#log(slot, level, message));
        monitor.on('finding', (finding) => this.#broadcast(slot, 'finding', finding));
        monitor.on('status', (status) => this.#broadcast(slot, 'status', status));
        monitor.on('targets', () => this.#refreshReport(slot));
        try {
            await monitor.start();
            this.#broadcastState(slot);
            this.#refreshReport(slot);
        } catch (error) {
            slot.configError = (error as Error).message;
            this.#broadcastState(slot);
        }
    }

    #snapshot(slot: Slot): unknown {
        const runtime = slot.monitor?.runtime;
        const targets = runtime?.ctx.targets;
        const watched = targets ? watchedSubjects(targets) : new Set<string>();
        const recorded = runtime ? runtime.state.findings().filter((f) => watched.has(f.subject)) : [];
        const findings = recorded.toSorted((a, b) => b.slot - a.slot).slice(0, FEED_LIMIT);
        const severityCounts: Record<string, number> = {};
        for (const f of recorded) severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
        return {
            monitor: slot.id,
            monitors: this.#monitorList(),
            severityCounts,
            readOnly: this.#options.readOnly,
            paused: slot.paused,
            configured: Boolean(runtime),
            configError: slot.configError,
            apiKeySet: Boolean(process.env.HELIUS_API_KEY),
            config: this.#options.readOnly ? null : this.#editableConfig(slot),
            status: slot.monitor?.status() ?? null,
            watching: targets
                ? {
                      programs: Object.fromEntries([...targets.programs.values()].map((p) => [p.id, p.label])),
                      multisigs: targets.multisigs.size,
                      mints: targets.mints.size,
                      treasuries: [...targets.treasuries.values()].filter((t) => !t.discovered).length,
                      vaults: [...targets.treasuries.values()].filter((t) => t.discovered).length,
                      keys: targets.privilegedKeys.size,
                  }
                : null,
            posture: slot.report?.posture ?? null,
            reportGeneratedAt: slot.report?.generatedAt ?? null,
            reportRunning: slot.reportRunning,
            reportError: slot.reportError,
            findings,
            logs: slot.logs,
        };
    }

    /** What the tab bar needs for every monitor. */
    #monitorList(): { id: string; name: string; phase: string }[] {
        return [...this.#slots.values()].map((slot) => {
            const raw = this.#savedConfig(slot);
            const programs = (raw?.programs ?? []) as { name?: string; id?: string }[];
            const name = (typeof raw?.name === 'string' && raw.name) || programs[0]?.name || programs[0]?.id || 'New monitor';
            const phase = slot.paused
                ? 'paused'
                : slot.configError
                  ? 'error'
                  : slot.monitor
                    ? slot.monitor.status().phase
                    : programs.length === 0
                      ? 'unconfigured'
                      : 'starting';
            return { id: slot.id, name, phase };
        });
    }

    #savedConfig(slot: Slot): Record<string, unknown> | null {
        return existsSync(slot.configPath) ? ((readRawConfig(slot.configPath) as Record<string, unknown> | null) ?? {}) : null;
    }

    #editableConfig(slot: Slot): unknown {
        const saved = this.#savedConfig(slot);
        return saved && maskSecrets(saved);
    }

    async #saveConfig(slot: Slot, body: unknown): Promise<unknown> {
        const { config } = body as { config?: Record<string, unknown> };
        if (!config || typeof config !== 'object') throw new Error('Missing config');
        const document = fromBrowser(config, this.#savedConfig(slot));
        mkdirSync(dirname(slot.configPath), { recursive: true });
        saveConfig(slot.configPath, document);
        this.#log(slot, 'success', 'Configuration saved; restarting the monitor');
        return this.#reload(slot);
    }

    /** Re-reads `.env` and the config and restarts the monitor; also ends a pause. */
    async #reload(slot: Slot): Promise<unknown> {
        const resuming = slot.paused;
        slot.paused = false;
        await slot.monitor?.stop();
        slot.monitor = null;
        slot.report = null;
        slot.reportError = null;
        if (resuming) this.#log(slot, 'success', 'Monitoring started; catching up on what happened while stopped');
        await this.#startMonitor(slot);
        return this.#snapshot(slot);
    }

    async #pause(slot: Slot): Promise<unknown> {
        if (!slot.monitor || slot.paused) return this.#snapshot(slot);
        await slot.monitor.stop();
        slot.paused = true;
        this.#log(slot, 'warn', 'Monitoring stopped from the dashboard: the stream is closed and no alerts are sent');
        this.#broadcastState(slot);
        return this.#snapshot(slot);
    }

    /** A new, empty monitor with its own config and state file. */
    #createMonitor(body: unknown): unknown {
        const { name } = body as { name?: unknown };
        if (typeof name !== 'string' || !name.trim()) throw new Error('Give the monitor a name');
        const base =
            name
                .trim()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-|-$/g, '')
                .slice(0, 32) || 'monitor';
        let id = base;
        for (let n = 2; this.#slots.has(id) || id === DEFAULT_ID || existsSync(join(this.#monitorsDir, `${id}.yaml`)); n++)
            id = `${base}-${n}`;
        mkdirSync(this.#monitorsDir, { recursive: true });
        const configPath = join(this.#monitorsDir, `${id}.yaml`);
        writeFileSync(configPath, stringify({ name: name.trim(), stateFile: `.watchtower/${id}.json` }));
        const slot = this.#addSlot(id, configPath);
        this.#log(slot, 'info', 'Not configured yet. Open the Setup tab to add a program.');
        this.#broadcastState(slot);
        return this.#snapshot(slot);
    }

    /** Removes a stopped or unconfigured monitor's config and history. Alert-channel secrets stay in `.env`. */
    async #deleteMonitor(slot: Slot): Promise<unknown> {
        if (slot.monitor && !slot.paused) throw new Error('Stop the monitor before deleting it');
        await slot.monitor?.stop();
        const raw = this.#savedConfig(slot);
        const stateFile = typeof raw?.stateFile === 'string' ? raw.stateFile : DEFAULT_STATE_FILE;
        rmSync(slot.configPath, { force: true });
        rmSync(resolve(stateFile), { force: true });
        this.#slots.delete(slot.id);
        if (this.#slots.size === 0) this.#addSlot(DEFAULT_ID, this.#options.configPath);
        this.#broadcast(null, 'monitors', this.#monitorList());
        return { monitors: this.#monitorList() };
    }

    async #discover(body: unknown): Promise<unknown> {
        const { kind, address } = body as { kind?: string; address?: string };
        loadEnvFile();
        const key = process.env.HELIUS_API_KEY;
        if (!key) throw new Error(MISSING_API_KEY);
        if (!address || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) throw new Error('Enter a base58 address');
        const helius = heliusClient(key, endpointsFromEnv());
        const rpc = new RpcClient(helius);
        if (kind === 'mint') return { kind, ...(await discoverMint(rpc, address)) };
        if (kind === 'multisig') return { kind, ...(await loadMultisig(rpc, address)) };
        return { kind: 'program', ...(await discoverProgram(rpc, new ParsedEventsClient(helius, key), address)) };
    }

    #refreshReport(slot: Slot): { started: boolean } {
        const runtime = slot.monitor?.runtime;
        if (!runtime || slot.reportRunning) return { started: false };
        slot.reportRunning = true;
        this.#broadcast(slot, 'report', { running: true });
        buildReport(runtime, slot.monitor!.status().coverage, { idlAlertMode: 'send', onWarning: (m) => this.#log(slot, 'warn', m) })
            .then((report) => {
                slot.report = report;
                slot.reportError = null;
                this.#log(slot, 'success', `Posture graded ${report.posture.grade} (${report.posture.score}/100)`);
            })
            .catch((error: Error) => {
                slot.reportError = error.message;
                this.#log(slot, 'error', `Report failed: ${error.message}`);
            })
            .finally(() => {
                slot.reportRunning = false;
                this.#broadcastState(slot);
            });
        return { started: true };
    }

    async #testAlert(slot: Slot): Promise<unknown> {
        const config = slot.monitor?.config;
        if (!config) throw new Error('Save a configuration first');
        const program = config.programs[0]!;
        const sample: Finding = {
            id: `test-${Date.now()}`,
            detector: 'test-alert',
            severity: 'critical',
            title: 'Test alert',
            description: `Watchtower can reach this channel. Real alerts for ${program.name ?? program.id} will look like this.`,
            subject: program.id,
            subjectLabel: program.name ?? program.id,
            signature: null,
            slot: 0,
            blockTime: Math.floor(Date.now() / 1000),
            details: { Source: 'Watchtower dashboard' },
        };
        const sinks = createSinks(config.alerts.sinks, 'info');
        const delivered = await dispatch(sinks, sample);
        this.#log(
            slot,
            delivered ? 'success' : 'error',
            delivered ? `Test alert sent to ${sinks.map((s) => s.name).join(', ')}` : 'Test alert failed for at least one channel',
        );
        return { delivered, sinks: sinks.map((s) => s.name) };
    }

    #reportHtml(slot: Slot, res: ServerResponse): void {
        if (!slot.report) return json(res, 404, { error: 'No report yet; refresh the posture from the dashboard' });
        res.writeHead(200, {
            'content-type': 'text/html; charset=utf-8',
            'content-disposition': `inline; filename="watchtower-${slot.id}-${slot.report.generatedAt.toISOString().slice(0, 10)}.html"`,
        });
        res.end(renderHtml({ ...slot.report, ...this.#coverage(slot) }));
    }

    /** The monitor's current coverage, since its scans can finish after the report was built. */
    #coverage(slot: Slot): Pick<ReportData, 'coverage' | 'coverageNote'> {
        const status = slot.monitor?.status();
        const coverage = status?.coverage ?? [];
        if (coverage.length > 0) return { coverage };
        if (!this.#options.backfill)
            return { coverage, coverageNote: 'History scans are off: the dashboard was started with --no-backfill.' };
        if (status?.phase === 'starting' || status?.phase === 'catching-up') {
            return { coverage, coverageNote: 'History scans are still running. Reload this page in a moment.' };
        }
        return { coverage, coverageNote: 'No history scans have run since the dashboard started.' };
    }

    #subscribe(res: ServerResponse): void {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
        res.write('retry: 3000\n\n');
        this.#clients.add(res);
        const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 25_000);
        res.on('close', () => {
            clearInterval(keepAlive);
            this.#clients.delete(res);
        });
    }

    /** Every event names its monitor (`null` for the monitor list), so one stream serves all tabs. */
    #broadcast(slot: Slot | null, event: string, data: unknown): void {
        const frame = `event: ${event}\ndata: ${toJson({ monitor: slot?.id ?? null, data })}\n\n`;
        for (const client of this.#clients) client.write(frame);
    }

    #broadcastState(slot: Slot): void {
        this.#broadcast(slot, 'state', this.#snapshot(slot));
        this.#broadcast(null, 'monitors', this.#monitorList());
    }

    #log(slot: Slot, level: LogLevel, message: string): void {
        const entry = { time: Date.now(), level, message };
        slot.logs = [...slot.logs.slice(-(LOG_LIMIT - 1)), entry];
        this.#broadcast(slot, 'log', entry);
    }

    #static(pathname: string, res: ServerResponse): void {
        const file = new URL(`.${pathname}`, UI_DIR);
        const type = STATIC_TYPES[extname(file.pathname)];
        if (!type || !resolve(file.pathname).startsWith(resolve(UI_DIR.pathname))) return json(res, 404, { error: 'Not found' });
        sendFile(res, file, type);
    }

    /** On loopback, only localhost Host headers are accepted, which defeats DNS rebinding. */
    #hostAllowed(req: IncomingMessage): boolean {
        if (!LOOPBACK_HOSTS.has(this.#options.host)) return true;
        const host = (req.headers.host ?? '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
        return LOOPBACK_HOSTS.has(host);
    }

    #authorized(req: IncomingMessage): boolean {
        const password = this.#options.password;
        if (!password) return true;
        const [scheme, encoded] = (req.headers.authorization ?? '').split(' ');
        if (scheme !== 'Basic' || !encoded) return false;
        const supplied = Buffer.from(Buffer.from(encoded, 'base64').toString().split(':').slice(1).join(':'));
        const expected = Buffer.from(password);
        return supplied.length === expected.length && timingSafeEqual(supplied, expected);
    }
}

/** Blocks cross-site form posts: browsers cannot send `application/json` cross-origin without a preflight we never grant. */
function sameOriginJson(req: IncomingMessage): boolean {
    if (!(req.headers['content-type'] ?? '').startsWith('application/json')) return false;
    const origin = req.headers.origin;
    return !origin || new URL(origin).host === req.headers.host;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
    let size = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > MAX_BODY_BYTES) throw new Error('Request body too large');
        chunks.push(chunk as Buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

function json(res: ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(toJson(body));
}

function toJson(value: unknown): string {
    return JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v));
}

function sendFile(res: ServerResponse, file: URL, type: string): void {
    if (!existsSync(file)) return json(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-cache' });
    res.end(readFileSync(file));
}
