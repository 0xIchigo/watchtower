import {
    makeParsedStreamsClient,
    type ParsedStreamsClient as SdkStreamsClient,
    type ParsedTransactionFilter,
    type ParsedTransactionSubscription,
    type ParsedTransactionValue,
} from 'helius-sdk/websockets/parsedStreams';
import WebSocket from 'ws';

export type StreamFilter = ParsedTransactionFilter;

export interface Subscription {
    label: string;
    filter: StreamFilter;
}

interface StreamHandlers {
    onTransaction(value: ParsedTransactionValue, label: string): void;
    /** Runs once every subscription is in place, on the first connection and after each reconnect. `rejected` lists skipped subscriptions. */
    onConnected?(info: { reconnect: boolean; rejected: string[] }): void | Promise<void>;
    /** Runs as soon as a connection drops, before the SDK reconnects. */
    onDisconnected?(info: { code: number; reason: string }): void;
    /** Slot of each notification; delivery is in order per connection, so earlier slots have all arrived. */
    onSlot?(slot: number): void;
    onError?(error: Error): void;
}

/** JSON-RPC codes for invalid params and filter limits; resubscribing with the same filter fails again. */
const REJECTED_FILTER_CODES = new Set([-32602, -32000]);
const MAX_RESTART_BACKOFF_MS = 30_000;

/**
 * The SDK resubscribes on reconnect. Sockets come from `ws` so the SDK sees server pings, and report a drop immediately
 * (the SDK only reports a restored reconnect). If the SDK gives up, a fresh client is started.
 */
export class ParsedStreamsClient {
    readonly #url: string | undefined;
    readonly #apiKey: string;
    readonly #subscriptions: Subscription[];
    readonly #handlers: StreamHandlers;
    #client: SdkStreamsClient | undefined;
    #generation = 0;
    #restarts = 0;
    #restartTimer: NodeJS.Timeout | undefined;
    #stopped = false;

    /** `url` overrides the SDK's Parsed Streams endpoint; the API key is added to it. */
    constructor(url: string | undefined, apiKey: string, subscriptions: Subscription[], handlers: StreamHandlers) {
        this.#url = url;
        this.#apiKey = apiKey;
        this.#subscriptions = subscriptions;
        this.#handlers = handlers;
    }

    start(): void {
        this.#stopped = false;
        void this.#open(false);
    }

    stop(): void {
        this.#stopped = true;
        this.#generation++;
        clearTimeout(this.#restartTimer);
        this.#client?.close();
    }

    async #open(reconnect: boolean): Promise<void> {
        const generation = ++this.#generation;
        const current = () => generation === this.#generation && !this.#stopped;
        const handlers = this.#handlers;
        class TrackedSocket extends WebSocket {
            constructor(url: string) {
                super(url);
                this.on('close', (code, reason) => current() && handlers.onDisconnected?.({ code, reason: reason.toString() }));
            }
        }
        const client = makeParsedStreamsClient(this.#apiKey, {
            ...(this.#url ? { url: withApiKey(this.#url, this.#apiKey) } : {}),
            WebSocket: TrackedSocket,
            onReconnect: () => current() && void this.#connected(true, rejected),
        });
        this.#client = client;
        const rejected: string[] = [];

        for (const { label, filter } of this.#subscriptions) {
            let subscription: ParsedTransactionSubscription;
            try {
                subscription = await client.parsedTransactionSubscribe(
                    { includeFailed: false, includeCpi: true, ...filter },
                    { commitment: 'confirmed', details: 'full' },
                );
            } catch (error) {
                const code = (error as { code?: number }).code;
                if (code !== undefined && REJECTED_FILTER_CODES.has(code)) {
                    handlers.onError?.(new Error(`Subscription ${label} was rejected and is skipped: ${(error as Error).message}`));
                    rejected.push(label);
                    continue;
                }
                this.#restart(generation, error as Error);
                return;
            }
            void this.#consume(subscription, label, generation);
        }
        if (!current()) return;
        this.#restarts = 0;
        await this.#connected(reconnect, rejected);
    }

    async #consume(subscription: ParsedTransactionSubscription, label: string, generation: number): Promise<void> {
        try {
            for await (const { context, value } of subscription) {
                if (generation !== this.#generation) return;
                this.#handlers.onTransaction(value, label);
                this.#handlers.onSlot?.(context.slot);
            }
        } catch (error) {
            this.#restart(generation, error as Error);
        }
    }

    async #connected(reconnect: boolean, rejected: string[]): Promise<void> {
        try {
            await this.#handlers.onConnected?.({ reconnect, rejected });
        } catch (error) {
            this.#handlers.onError?.(error as Error);
        }
    }

    /** Starts a new client once the SDK gives up: reconnects exhausted, or it fell too far behind. */
    #restart(generation: number, error: Error): void {
        if (generation !== this.#generation || this.#stopped) return;
        this.#generation++;
        this.#client?.close();
        const retryInMs = Math.min(MAX_RESTART_BACKOFF_MS, 1_000 * 2 ** this.#restarts++);
        this.#handlers.onError?.(new Error(`Parsed Streams stopped: ${error.message}. Starting a new connection in ${retryInMs / 1000}s.`));
        this.#restartTimer = setTimeout(() => void this.#open(true), retryInMs);
    }
}

function withApiKey(url: string, apiKey: string): string {
    const parsed = new URL(url);
    parsed.searchParams.set('api-key', apiKey);
    return parsed.toString();
}
