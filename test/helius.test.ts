import type { HeliusClient } from 'helius-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ParsedStreamsClientOptions } from 'helius-sdk/websockets/parsedStreams';

/** A fake SDK Parsed Streams client: each subscription is an async queue the test pushes into or fails. */
interface FakeSdkClient {
    options: ParsedStreamsClientOptions;
    filters: unknown[];
    closed: boolean;
    queues: { push(n: unknown): void; fail(e: Error): void }[];
}
const sdkClients: FakeSdkClient[] = [];

vi.mock('helius-sdk/websockets/parsedStreams', () => ({
    makeParsedStreamsClient: (_key: string, options: ParsedStreamsClientOptions) => {
        const client: FakeSdkClient = { options, filters: [], closed: false, queues: [] };
        sdkClients.push(client);
        return {
            close: () => (client.closed = true),
            parsedTransactionSubscribe: async (filter: { programs?: string[] }) => {
                client.filters.push(filter);
                if (filter.programs?.[0] === 'bad') throw Object.assign(new Error('invalid params'), { code: -32602 });
                const items: unknown[] = [];
                let wake: (() => void) | undefined;
                let failure: Error | undefined;
                client.queues.push({
                    push: (n) => (items.push(n), wake?.()),
                    fail: (e) => ((failure = e), wake?.()),
                });
                return {
                    async *[Symbol.asyncIterator]() {
                        for (;;) {
                            if (failure) throw failure;
                            const next = items.shift();
                            if (next) yield next;
                            else await new Promise<void>((r) => (wake = r));
                        }
                    },
                };
            },
        };
    },
}));

const { ParsedStreamsClient } = await import('../src/helius/parsedStreams.js');
const { ParsedEventsClient } = await import('../src/helius/parsedEvents.js');

afterEach(() => {
    sdkClients.length = 0;
    vi.useRealTimers();
});

function handlers() {
    return { onTransaction: vi.fn(), onConnected: vi.fn(), onDisconnected: vi.fn(), onSlot: vi.fn(), onError: vi.fn() };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('Parsed Streams through the SDK', () => {
    it('subscribes every filter, skips a rejected one, and reports transactions then their slot', async () => {
        const h = handlers();
        const client = new ParsedStreamsClient(
            undefined,
            'k',
            [
                { label: 'bad', filter: { programs: ['bad'] } },
                { label: 'admin', filter: { programs: ['Prog'] } },
            ],
            h,
        );
        client.start();
        await flush();
        expect(h.onError.mock.calls[0]![0].message).toMatch(/Subscription bad was rejected/);
        expect(h.onConnected).toHaveBeenCalledWith({ reconnect: false, rejected: ['bad'] });
        expect(sdkClients[0]!.filters[1]).toMatchObject({ programs: ['Prog'], includeFailed: false, includeCpi: true });

        sdkClients[0]!.queues[0]!.push({ context: { slot: 42 }, value: { transaction: { signature: 's' } } });
        await flush();
        expect(h.onTransaction).toHaveBeenCalledWith({ transaction: { signature: 's' } }, 'admin');
        expect(h.onSlot).toHaveBeenCalledWith(42);
        expect(h.onTransaction.mock.invocationCallOrder[0]).toBeLessThan(h.onSlot.mock.invocationCallOrder[0]!);
        client.stop();
    });

    it('runs the gap-fill again when the SDK restores a dropped connection', async () => {
        const h = handlers();
        const client = new ParsedStreamsClient(undefined, 'k', [{ label: 'a', filter: { programs: ['P'] } }], h);
        client.start();
        await flush();
        sdkClients[0]!.options.onReconnect!({ closeCode: 1006, lastSlot: 10 });
        await flush();
        expect(h.onConnected).toHaveBeenLastCalledWith({ reconnect: true, rejected: [] });
        client.stop();
    });

    it('starts a fresh client when the SDK gives up, and ignores the old one', async () => {
        vi.useFakeTimers();
        const h = handlers();
        const client = new ParsedStreamsClient('wss://example.com/', 'k', [{ label: 'a', filter: { programs: ['P'] } }], h);
        client.start();
        await vi.advanceTimersByTimeAsync(0);
        expect(sdkClients[0]!.options.url).toBe('wss://example.com/?api-key=k');

        sdkClients[0]!.queues[0]!.fail(new Error('gave up after 10 reconnect attempts'));
        await vi.advanceTimersByTimeAsync(0);
        expect(sdkClients[0]!.closed).toBe(true);
        expect(h.onError.mock.calls.at(-1)![0].message).toMatch(/gave up.*new connection in 1s/);
        await vi.advanceTimersByTimeAsync(1_000);
        expect(sdkClients).toHaveLength(2);
        expect(h.onConnected).toHaveBeenLastCalledWith({ reconnect: true, rejected: [] });
        client.stop();
    });

    it('reports a dropped socket at once, before the SDK reconnects', async () => {
        const h = handlers();
        const client = new ParsedStreamsClient(undefined, 'k', [], h);
        client.start();
        await flush();
        const Socket = sdkClients[0]!.options.WebSocket as unknown as new (url: string) => {
            on(event: string, listener: () => void): void;
        };
        new Socket('ws://127.0.0.1:9').on('error', () => {});
        await vi.waitFor(() => expect(h.onDisconnected).toHaveBeenCalledWith(expect.objectContaining({ code: 1006 })));
        client.stop();
    });
});

describe('Parsed Events through the SDK', () => {
    const page = (data: string[], token?: string) => ({
        data: data.map((signature) => ({ signature })),
        paginationToken: token,
        scan: { stoppedOn: 'budget', scannedTransactions: 100, matchedTransactions: data.length, creditsCharged: 10 },
    });

    it('retries rate limits and follows pagination to the end', async () => {
        vi.useFakeTimers();
        const scan = vi
            .fn()
            .mockRejectedValueOnce(new Error('Helius HTTP 429: Too many requests'))
            .mockResolvedValueOnce(page(['a'], 'next'))
            .mockResolvedValueOnce(page(['b']));
        const events = new ParsedEventsClient({ parsedEvents: { scan } } as unknown as HeliusClient, 'k');
        const seen: string[] = [];
        const run = (async () => {
            for await (const r of events.scanAll({ address: 'A', match: { programs: [{ programId: 'P' }] } }, 1_000))
                seen.push(r.signature);
        })();
        await vi.advanceTimersByTimeAsync(5_000);
        await run;
        expect(seen).toEqual(['a', 'b']);
        expect(scan).toHaveBeenCalledTimes(3);
        expect(scan.mock.calls[2]![0]).toMatchObject({ commitment: 'confirmed', paginationToken: 'next' });
    });

    it('does not retry a rejected request', async () => {
        const scan = vi.fn().mockRejectedValue(new Error('Helius HTTP 400: instruction not in IDL'));
        const events = new ParsedEventsClient({ parsedEvents: { scan } } as unknown as HeliusClient, 'k');
        await expect(events.scan({ address: 'A', match: { programs: [{ programId: 'P' }] } })).rejects.toThrow(
            'Parsed Events scan failed: Helius HTTP 400',
        );
        expect(scan).toHaveBeenCalledTimes(1);
    });
});
