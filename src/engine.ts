import { severityRank } from './config.js';
import { linkAttackStages, runDetectors } from './detectors/index.js';
import type { DetectorContext, Finding, FindingAnchor } from './detectors/types.js';
import type { ParsedTx } from './model.js';
import { dispatch, type Sink } from './sinks.js';

/** `send` alerts now (failed deliveries stay queued), `queue` alerts on the next `watch` start, `silent` only records. */
export type AlertMode = 'send' | 'queue' | 'silent';

const RECENT_SIGNATURES = 20_000;
const MAX_LISTED_TRANSACTIONS = 10;

/** One message to the sinks: a finding, or a summary standing in for several. `ids` are marked delivered together. */
interface Alert {
    finding: Finding;
    ids: string[];
}

export class Engine {
    readonly #ctx: DetectorContext;
    readonly #sinks: Sink[];
    readonly #onRecord: ((finding: Finding) => void) | undefined;
    readonly #enrich: ((finding: Finding) => Promise<void>) | undefined;
    readonly #groupWindowMs: number;
    readonly #recent = new Set<string>();
    /** Repeats held after the first alert of a group was sent, until the window closes. */
    readonly #windows = new Map<string, { held: Finding[]; timer: NodeJS.Timeout }>();
    #outbox: Alert[] = [];
    #draining: Promise<void> | undefined;

    /**
     * `enrich` runs on each new finding before it is recorded. With `groupWindowMs`, repeats of a non-critical alert
     * (same `groupKey`) within that long of the first are sent as one summary when the window closes.
     */
    constructor(
        ctx: DetectorContext,
        sinks: Sink[],
        onRecord?: (finding: Finding) => void,
        enrich?: (finding: Finding) => Promise<void>,
        groupWindowMs = 0,
    ) {
        this.#ctx = ctx;
        this.#sinks = sinks;
        this.#onRecord = onRecord;
        this.#enrich = enrich;
        this.#groupWindowMs = groupWindowMs;
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

    /** Sends every held repeat now, then waits for delivery. */
    async close(): Promise<void> {
        for (const key of this.#windows.keys()) this.#closeWindow(key);
        await this.idle();
    }

    #send(finding: Finding): void {
        if (this.#groupWindowMs <= 0 || finding.severity === 'critical') return this.#enqueue({ finding, ids: [finding.id] });
        const key = groupKey(finding);
        const open = this.#windows.get(key);
        if (open) {
            open.held.push(finding);
            return;
        }
        this.#enqueue({ finding, ids: [finding.id] });
        const timer = setTimeout(() => this.#closeWindow(key), this.#groupWindowMs);
        timer.unref();
        this.#windows.set(key, { held: [], timer });
    }

    #closeWindow(key: string): void {
        const window = this.#windows.get(key);
        if (!window) return;
        clearTimeout(window.timer);
        this.#windows.delete(key);
        if (window.held.length > 0) this.#enqueue(combine(window.held, true));
    }

    #enqueue(alert: Alert): void {
        this.#outbox.push(alert);
        this.#draining ??= this.#drain();
    }

    /** Delivers most severe first, so a slow channel delays low-severity alerts rather than critical ones. */
    async #drain(): Promise<void> {
        try {
            while (this.#outbox.length > 0) {
                this.#outbox.sort((a, b) => severityRank(b.finding.severity) - severityRank(a.finding.severity));
                await this.#deliver(this.#outbox.shift()!);
            }
        } finally {
            this.#draining = undefined;
        }
    }

    /** Delivers alerts left over from an earlier run, repeats combined as they would have been live. */
    async flushPendingAlerts(): Promise<number> {
        const pending = this.#ctx.state.pendingAlerts();
        const groups = new Map<string, Finding[]>();
        for (const finding of pending) {
            const key = this.#groupWindowMs > 0 && finding.severity !== 'critical' ? groupKey(finding) : finding.id;
            groups.set(key, [...(groups.get(key) ?? []), finding]);
        }
        for (const findings of groups.values()) await this.#deliver(combine(findings, false));
        return pending.length;
    }

    async #deliver(alert: Alert): Promise<void> {
        if (!(await dispatch(this.#sinks, alert.finding))) return;
        for (const id of alert.ids) this.#ctx.state.markDelivered(id);
    }

    #remember(signature: string): void {
        this.#recent.add(signature);
        if (this.#recent.size > RECENT_SIGNATURES) {
            const oldest = this.#recent.values().next().value;
            if (oldest !== undefined) this.#recent.delete(oldest);
        }
    }
}

/** Alerts that say the same thing about the same subject, such as one admin call repeated across markets. */
function groupKey(finding: Finding): string {
    return `${finding.detector}|${finding.subject}|${finding.title}`;
}

/**
 * One alert for `findings`, oldest first. A single finding is sent as is; several become a summary at the highest
 * severity among them. `afterFirst` says the group's first alert was already sent on its own.
 */
function combine(findings: Finding[], afterFirst: boolean): Alert {
    const first = findings[0]!;
    const last = findings.at(-1)!;
    const ids = findings.map((f) => f.id);
    if (findings.length === 1) return { finding: first, ids };
    const n = findings.length;
    const severity = findings.reduce((top, f) => (severityRank(f.severity) > severityRank(top) ? f.severity : top), first.severity);
    const when = (f: Finding) => (f.blockTime ? `${new Date(f.blockTime * 1000).toISOString().slice(11, 16)} UTC` : `slot ${f.slot}`);
    const signatures = findings.map((f) => (f.signature ? `${f.signature.slice(0, 8)}…` : `slot ${f.slot}`));
    const listed = signatures.slice(0, MAX_LISTED_TRANSACTIONS).join(', ');
    return {
        ids,
        finding: {
            ...last,
            id: `${last.id}:group`,
            severity,
            title: afterFirst ? `${first.title}: ${n} more` : `${first.title} (×${n})`,
            description: `${n} ${afterFirst ? 'more alerts' : 'alerts'} like this for ${first.subjectLabel} between ${when(first)} and ${when(last)}. The latest: ${last.description}`,
            details: {
                Transactions: n > MAX_LISTED_TRANSACTIONS ? `${listed}, and ${n - MAX_LISTED_TRANSACTIONS} more` : listed,
                ...last.details,
            },
        },
    };
}
