import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { backfill } from '../backfill.js';
import { loadConfig } from '../config.js';
import { buildReport, reportJson } from '../report/build.js';
import { renderHtml, renderTerminal } from '../report/render.js';
import { createRuntime } from '../runtime.js';

export interface ReportOptions {
    config: string;
    html?: string | false;
    json?: string;
}

export async function reportCommand(options: ReportOptions): Promise<void> {
    const config = loadConfig(options.config);
    const spinner = p.spinner();

    spinner.start('Discovering upgrade authorities, multisigs and mints');
    const runtime = await createRuntime(config).catch((error: Error) => {
        spinner.error('Discovery failed');
        throw error;
    });
    const currentSlot = await runtime.rpc.getSlot();
    spinner.stop('Discovery complete');

    spinner.start('Scanning history with Parsed Events');
    const scanStartedAt = Date.now();
    const coverage = await backfill(config, runtime.events, runtime.engine, runtime.state, runtime.plans, currentSlot, {
        alertMode: 'queue',
        onProgress: (plan, progress) =>
            spinner.message(`${plan.label}: ${progress.scannedTransactions.toLocaleString('en-US')} transactions scanned`),
    });
    const failed = coverage.filter((c) => c.error);
    const elapsed = `${((Date.now() - scanStartedAt) / 1000).toFixed(1)}s`;
    if (failed.length > 0) spinner.error(`${failed.length} of ${coverage.length} scans failed (${elapsed})`);
    else spinner.stop(`History scanned in ${elapsed}`);

    spinner.start('Checking IDLs and durable nonce accounts');
    const report = await buildReport(runtime, coverage, {
        idlAlertMode: 'queue',
        onWarning: (message) => console.warn(message),
    });
    spinner.stop('Checks complete');

    console.log(renderTerminal(report));

    const queued = runtime.state.pendingAlerts().length;
    if (queued > 0) console.log(pc.yellow(`\n${queued} new event(s) since the last run are queued; \`watchtower watch\` delivers them.`));
    if (failed.length > 0) process.exitCode = 1;

    if (options.html !== false) {
        const path = writeOutput(
            options.html ?? `reports/watchtower-${report.generatedAt.toISOString().slice(0, 10)}.html`,
            renderHtml(report),
        );
        console.log(`\n${pc.bold('HTML report:')} ${path}`);
    }
    if (options.json) console.log(`${pc.bold('JSON report:')} ${writeOutput(options.json, reportJson(report))}`);
}

function writeOutput(file: string, contents: string): string {
    const path = resolve(file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents);
    return path;
}
