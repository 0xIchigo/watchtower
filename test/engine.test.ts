import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Finding } from '../src/detectors/types.js';
import { Engine } from '../src/engine.js';
import type { Sink } from '../src/sinks.js';
import { context, KEYS } from './helpers.js';

const WINDOW_MS = 600_000;

let n = 0;
function finding(title: string, severity: Finding['severity'] = 'medium'): Finding {
    n++;
    return {
        id: `privileged-instruction:sig${n}:0`,
        detector: 'privileged-instruction',
        severity,
        title,
        description: `call ${n}`,
        subject: KEYS.program,
        subjectLabel: 'Perps',
        signature: `sig${n}aaaaaaaaaaaa`,
        slot: 1_000 + n,
        blockTime: 1_775_059_539 + n * 60,
        details: { Market: `market ${n}` },
    };
}

function capture(): { sink: Sink; sent: Finding[] } {
    const sent: Finding[] = [];
    return { sent, sink: { name: 'test', minSeverity: 'info', send: async (f) => void sent.push(f) } };
}

afterEach(() => vi.useRealTimers());

describe('alert grouping', () => {
    it('sends the first alert at once and its repeats as one summary when the window closes', async () => {
        vi.useFakeTimers();
        const ctx = context();
        const { sink, sent } = capture();
        const engine = new Engine(ctx, [sink], undefined, undefined, WINDOW_MS);
        const repeats = Array.from({ length: 27 }, () => finding('Risk setting changed: update_withdraw_guard_threshold'));
        for (const f of repeats) await engine.record(f, 'send');
        await engine.idle();
        expect(sent.map((f) => f.title)).toEqual(['Risk setting changed: update_withdraw_guard_threshold']);

        await vi.advanceTimersByTimeAsync(WINDOW_MS);
        await engine.idle();
        expect(sent).toHaveLength(2);
        expect(sent[1]).toMatchObject({ title: 'Risk setting changed: update_withdraw_guard_threshold: 26 more', severity: 'medium' });
        expect(sent[1]!.details.Transactions).toMatch(/, and 16 more$/);
        expect(ctx.state.pendingAlerts()).toEqual([]);
        expect(ctx.state.findings()).toHaveLength(27);
    });

    it('never holds back a critical alert, and keeps different alerts apart', async () => {
        vi.useFakeTimers();
        const { sink, sent } = capture();
        const engine = new Engine(context(), [sink], undefined, undefined, WINDOW_MS);
        for (const f of [
            finding('Possible attack in progress', 'critical'),
            finding('Possible attack in progress', 'critical'),
            finding('Oracle changed', 'high'),
            finding('Limit raised'),
        ]) {
            await engine.record(f, 'send');
        }
        await engine.idle();
        expect(sent.map((f) => f.title)).toEqual([
            'Possible attack in progress',
            'Possible attack in progress',
            'Oracle changed',
            'Limit raised',
        ]);
    });

    it('sends held repeats on close, so stopping a monitor loses none', async () => {
        const ctx = context();
        const { sink, sent } = capture();
        const engine = new Engine(ctx, [sink], undefined, undefined, WINDOW_MS);
        for (const f of [finding('Limit raised'), finding('Limit raised'), finding('Limit raised', 'high')]) await engine.record(f, 'send');
        await engine.close();
        expect(sent.map((f) => [f.title, f.severity])).toEqual([
            ['Limit raised', 'medium'],
            ['Limit raised: 2 more', 'high'],
        ]);
        expect(ctx.state.pendingAlerts()).toEqual([]);
    });

    it('combines repeats among alerts left undelivered by an earlier run', async () => {
        const ctx = context();
        for (const f of [finding('Limit raised'), finding('Limit raised'), finding('Limit raised'), finding('Oracle changed', 'high')]) {
            await new Engine(ctx, []).record(f, 'queue');
        }
        const { sink, sent } = capture();
        expect(await new Engine(ctx, [sink], undefined, undefined, WINDOW_MS).flushPendingAlerts()).toBe(4);
        expect(sent.map((f) => f.title)).toEqual(['Limit raised (×3)', 'Oracle changed']);
        expect(ctx.state.pendingAlerts()).toEqual([]);
    });

    it('sends every alert on its own when grouping is off', async () => {
        const { sink, sent } = capture();
        const engine = new Engine(context(), [sink]);
        for (const f of [finding('Limit raised'), finding('Limit raised')]) await engine.record(f, 'send');
        await engine.idle();
        expect(sent).toHaveLength(2);
    });
});
