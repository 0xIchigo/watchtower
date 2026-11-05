import { severityRank } from './config.js';
import { linkAttackStages, runDetectors } from './detectors/index.js';
import type { DetectorContext, Finding, FindingAnchor } from './detectors/types.js';
import type { ParsedTx } from './model.js';
import { dispatch, type Sink } from './sinks.js';

/** `send` alerts now (failed deliveries stay queued), `queue` alerts on the next `watch` start, `silent` only records. */
export type AlertMode = 'send' | 'queue' | 'silent';

const RECENT_SIGNATURES = 20_000;

export class Engine {
    readonly #ctx: DetectorContext;
    readonly #sinks: Sink[];
    readonly #onRecord: ((finding: Finding) => void) | undefined;
    readonly #enrich: ((finding: Finding) => Promise<void>) | undefined;
    readonly #recent = new Set<string>();
    #outbox: Finding[] = [];
    #draining: Promise<void> | undefined;

    /** `enrich` runs on each new finding before it is recorded. */
    constructor(ctx: DetectorContext, sinks: Sink[], onRecord?: (finding: Finding) => void, enrich?: (finding: Finding) => Promise<void>) {
        this.#ctx = ctx;
        this.#sinks = sinks;
        this.#onRecord = onRecord;
        this.#enrich = enrich;
    }

    async process(tx: ParsedTx, alertMode: (finding: Finding) => AlertMode): Promise<Finding[]> {
        if (this.#recent.has(tx.signature)) return [];
        const findings = runDetectors(tx, this.#ctx);
        for (const finding of findings) {
            if (!this.#ctx.state.hasFinding(finding.id)) await this.#enrich?.(finding);
        }
        const fresh: Finding[] = [];
        for (const finding of [...findings, ...linkAttackStages(tx, findings, this.#ctx)]) {
            if (await this.record(finding, alertMode(finding))) fresh.push(finding);
        }
        this.#remember(tx.signature);
        return fresh;
    }

    async recordLinked(findings: Finding[], mode: AlertMode, anchor: FindingAnchor): Promise<number> {
        let recorded = 0;
        for (const finding of [...findings, ...linkAttackStages(anchor, findings, this.#ctx)]) {
            if (await this.record(finding, mode)) recorded++;
        }
        return recorded;
    }

    /** Returns false for a finding already recorded. `send` hands the alert to the outbox without waiting for delivery. */
    async record(finding: Finding, mode: AlertMode): Promise<boolean> {
        if (this.#ctx.state.hasFinding(finding.id)) return false;
        this.#ctx.state.addFinding(finding);
        if (mode !== 'silent') this.#ctx.state.queueAlert(finding.id);
        if (mode === 'send') this.#send(finding);
        this.#onRecord?.(finding);
        return true;
    }

    /** Resolves once every alert handed to the outbox has been attempted. */
    async idle(): Promise<void> {
        while (this.#draining) await this.#draining;
    }

    #send(finding: Finding): void {
        this.#outbox.push(finding);
        this.#draining ??= this.#drain();
    }

    /** Delivers most severe first, so a slow channel delays low-severity alerts rather than critical ones. */
    async #drain(): Promise<void> {
        try {
            while (this.#outbox.length > 0) {
                this.#outbox.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
                await this.#deliver(this.#outbox.shift()!);
            }
        } finally {
            this.#draining = undefined;
        }
    }

    async flushPendingAlerts(): Promise<number> {
        const pending = this.#ctx.state.pendingAlerts();
        for (const finding of pending) await this.#deliver(finding);
        return pending.length;
    }

    async #deliver(finding: Finding): Promise<void> {
        if (await dispatch(this.#sinks, finding)) this.#ctx.state.markDelivered(finding.id);
    }

    #remember(signature: string): void {
        this.#recent.add(signature);
        if (this.#recent.size > RECENT_SIGNATURES) {
            const oldest = this.#recent.values().next().value;
            if (oldest !== undefined) this.#recent.delete(oldest);
        }
    }
}
