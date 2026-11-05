import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import {
    endpointsFromEnv,
    loadConfig,
    loadEnvFile,
    parseConfig,
    requireApiKey,
    severityRank,
    type Config,
    type Severity,
} from '../config.js';
import type { Finding } from '../detectors/types.js';
import { fetchIdl } from '../discover/index.js';
import { ParsedEventsClient, type ScanRequest } from '../helius/parsedEvents.js';
import { RpcClient } from '../helius/rpc.js';
import { heliusClient } from '../helius/sdk.js';
import { fromParsedEvents, type ParsedTx } from '../model.js';
import { createRuntime } from '../runtime.js';
import { poweredByHelius } from '../style.js';

export interface ReplayOptions {
    config: string;
    program?: string[];
    from: string;
    to: string;
    budget: string;
    minSeverity: Severity;
    json?: string;
    programScans: boolean;
}

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
    critical: (t) => pc.bold(pc.red(t)),
    high: pc.red,
    medium: pc.yellow,
    low: pc.dim,
    info: pc.dim,
};

/** Transactions from all scan plans are merged and processed in slot order, so findings link across plans as they would live. */
export async function replayCommand(options: ReplayOptions): Promise<void> {
    const window: Pick<ScanRequest, 'slot' | 'time'> = {};
    for (const [flag, value, op] of [
        ['from', options.from, 'gte'],
        ['to', options.to, 'lte'],
    ] as const) {
        const [key, range] = bound(flag, value, op);
        window[key] = { ...window[key], ...range };
    }
    const budget = Number(options.budget);
    if (!Number.isInteger(budget) || budget <= 0) throw new Error('--budget must be a positive whole number');

    loadEnvFile();
    const apiKey = requireApiKey();
    const endpoints = endpointsFromEnv();
    const helius = heliusClient(apiKey, endpoints);
    const idlAtSlot = await slotAt(new RpcClient(helius), window.slot?.gte, window.time?.gte);
    const events = new ParsedEventsClient(helius, apiKey);
    const config = options.program?.length
        ? await adHocConfig(options.program, events, idlAtSlot, apiKey, endpoints)
        : loadConfig(options.config);
    config.stateFile = join(mkdtempSync(join(tmpdir(), 'watchtower-replay-')), 'state.json');
    config.alerts = { minSeverity: 'critical', sinks: [], groupWindowSeconds: 0 };

    const spinner = p.spinner();
    spinner.start('Discovering authorities, multisigs and vaults as they are today');
    const runtime = await createRuntime(config, { idlAtSlot });
    const { targets } = runtime.ctx;
    spinner.stop(
        `Watching ${targets.programs.size} program(s), ${targets.multisigs.size} multisig(s), ${targets.treasuries.size} treasury/vault(s)`,
    );

    const transactions = new Map<string, ParsedTx>();
    let credits = 0;
    const partial: string[] = [];
    const plans = runtime.plans.filter((plan) => options.programScans || !targets.programs.has(plan.address));
    for (const plan of plans) {
        spinner.start(`${plan.label}: scanning`);
        let ended = false;
        let scanned = 0;
        let planCredits = 0;
        const scan = runtime.events.scanAll(
            { address: plan.address, match: plan.match, status: plan.status, sortOrder: 'asc', limit: 100, ...window },
            budget,
            (progress) => {
                ended = progress.windowEnded;
                scanned = progress.scannedTransactions;
                planCredits = progress.creditsCharged;
                spinner.message(`${plan.label}: ${scanned.toLocaleString('en-US')} transactions scanned`);
            },
        );
        for await (const result of scan) {
            const tx = fromParsedEvents(result);
            if (tx) transactions.set(tx.signature, tx);
        }
        credits += planCredits;
        if (!ended) partial.push(plan.label);
        spinner.stop(
            `${plan.label}: ${scanned.toLocaleString('en-US')} scanned${ended ? '' : pc.yellow(' (budget reached, window not finished)')}`,
        );
    }

    const ordered = [...transactions.values()].sort((a, b) => a.slot - b.slot);
    const findings: Finding[] = [];
    for (const tx of ordered) findings.push(...(await runtime.engine.process(tx, () => 'silent')));

    printTimeline(findings, options.minSeverity, ordered.length);
    console.log(pc.dim(`\nParsed Events credits used by the scans: ${credits.toLocaleString('en-US')}`));
    if (partial.length > 0) console.log(pc.yellow(`\nNot fully scanned (raise --budget): ${partial.join(', ')}`));
    console.log(pc.dim('\nTargets reflect on-chain state today: current multisig members, authorities and vault balances.'));
    console.log(`\n${poweredByHelius()}`);

    if (options.json) {
        const path = resolve(options.json);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, JSON.stringify({ window: { from: options.from, to: options.to }, findings }, null, 2));
        console.log(`${pc.bold('JSON:')} ${path}`);
    }
}

/** The slot at the window start, estimated from the measured slot time when the window is given as a date. */
async function slotAt(rpc: RpcClient, slot: number | undefined, time: number | undefined): Promise<number> {
    if (slot !== undefined) return slot;
    const [current, slotMs] = await Promise.all([rpc.getSlot(), rpc.getSlotDurationMs()]);
    return time === undefined ? current : Math.round(current - ((Date.now() / 1000 - time) * 1000) / slotMs);
}

/** `--program <id>[:Name]`, with admin instructions from the IDL that was live when the window starts. */
async function adHocConfig(
    programs: string[],
    events: ParsedEventsClient,
    idlAtSlot: number,
    apiKey: string,
    endpoints: Config['endpoints'],
): Promise<Config> {
    const entries = await Promise.all(
        programs.map(async (spec) => {
            const [id = '', name] = spec.split(':');
            const idl = await fetchIdl(events, id, idlAtSlot);
            return { id, ...(name ? { name } : {}), privilegedInstructions: idl?.privileged ?? [] };
        }),
    );
    return { ...parseConfig({ programs: entries }, '--program'), apiKey, endpoints, configPath: '(command line)' };
}

/** `value` is a slot number or anything `Date.parse` reads. */
function bound(flag: string, value: string, op: 'gte' | 'lte'): ['slot' | 'time', { gte?: number; lte?: number }] {
    if (/^\d+$/.test(value)) return ['slot', { [op]: Number(value) }];
    const ms = Date.parse(value);
    if (Number.isNaN(ms)) throw new Error(`--${flag} must be a slot number or a date such as 2026-03-20`);
    return ['time', { [op]: Math.floor(ms / 1000) }];
}

function printTimeline(findings: Finding[], minSeverity: Severity, scanned: number): void {
    const shown = findings.filter((f) => severityRank(f.severity) >= severityRank(minSeverity)).sort((a, b) => a.slot - b.slot);
    console.log(
        `\n${pc.bold('Replay')}  ${findings.length} finding(s) in ${scanned.toLocaleString('en-US')} matching transactions; ${shown.length} at ${minSeverity} or above\n`,
    );
    for (const f of shown) {
        const when = f.blockTime ? new Date(f.blockTime * 1000).toISOString().replace('T', ' ').slice(0, 16) : `slot ${f.slot}`;
        const line = `${pc.dim(when)}  ${SEVERITY_COLOR[f.severity](f.severity.toUpperCase().padEnd(8))}  ${f.title} ${pc.dim(`· ${f.subjectLabel}`)}`;
        console.log(f.detector === 'attack-chain' ? pc.inverse(line) : line);
        if (severityRank(f.severity) >= severityRank('high')) console.log(pc.dim(`                    ${f.description}`));
    }
}
