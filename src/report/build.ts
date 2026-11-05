import type { BackfillResult } from '../backfill.js';
import { checkConfigChanges } from '../configWatch.js';
import { findNonceAccounts } from '../discover/index.js';
import type { AlertMode } from '../engine.js';
import { checkIdlChanges } from '../idlWatch.js';
import type { Runtime } from '../runtime.js';
import { watchedSubjects } from '../targets.js';
import { assessPosture, type NonceExposure } from './posture.js';
import type { ReportData } from './render.js';

export async function buildReport(
    runtime: Runtime,
    coverage: BackfillResult[],
    options: { idlAlertMode: AlertMode; onWarning?: (message: string) => void },
): Promise<ReportData> {
    const { config, ctx, state } = runtime;
    const currentSlot = await runtime.rpc.getSlot();
    await checkIdlChanges(runtime.events, runtime.engine, state, ctx.targets, options.idlAlertMode).catch((error: Error) =>
        options.onWarning?.(`Failed to check IDL versions: ${error.message}`),
    );
    await checkConfigChanges(runtime, options.idlAlertMode).catch((error: Error) =>
        options.onWarning?.(`Failed to check config accounts: ${error.message}`),
    );
    const keys = [...ctx.targets.privilegedKeys.values()];
    const nonces: NonceExposure = await findNonceAccounts(
        runtime.rpc,
        runtime.events,
        keys.map((k) => k.address),
    )
        .then((accounts) => ({ keys, accounts }))
        .catch((error: Error) => ({ error: `Listing nonce accounts failed: ${error.message}` }));

    const lookbackMs = config.backfill.lookbackDays * 86_400_000;
    const lookbackStartSlot = currentSlot - lookbackMs / runtime.slotMs;
    const lookbackStartTime = (Date.now() - lookbackMs) / 1000;
    const inWindow = (f: { slot: number; blockTime: number | null }) =>
        f.blockTime === null ? f.slot >= lookbackStartSlot : f.blockTime >= lookbackStartTime;
    const watched = watchedSubjects(ctx.targets);
    return {
        generatedAt: new Date(),
        lookbackDays: config.backfill.lookbackDays,
        posture: assessPosture(config, runtime.discovery, { currentSlot, slotMs: runtime.slotMs }, nonces),
        findings: state.findings().filter((f) => inWindow(f) && watched.has(f.subject)),
        coverage,
    };
}

/** JSON with bigint values as strings. */
export function reportJson(report: ReportData): string {
    return JSON.stringify(report, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
}
