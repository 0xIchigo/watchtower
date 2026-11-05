import pc from 'picocolors';
import { severityRank, type Severity, type SinkConfig } from './config.js';
import type { Finding } from './detectors/types.js';
import { brandBadge, HELIUS_ICON_URL } from './style.js';

export interface Sink {
    name: string;
    minSeverity: Severity;
    send(finding: Finding): Promise<void>;
}

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
    info: pc.gray,
    low: pc.blue,
    medium: pc.yellow,
    high: pc.red,
    critical: (text) => brandBadge(pc.bold(text)),
};

const SEVERITY_HEX: Record<Severity, number> = {
    info: 0x737373,
    low: 0x2e90fa,
    medium: 0xf79009,
    high: 0xf04438,
    critical: 0xe84326,
};

const SEVERITY_EMOJI: Record<Severity, string> = {
    info: '⚪',
    low: '🔵',
    medium: '🟡',
    high: '🔴',
    critical: '🚨',
};

export function findingUrl(f: Pick<Finding, 'signature' | 'subject'>): string {
    return f.signature ? `https://orbmarkets.io/tx/${f.signature}` : `https://orbmarkets.io/address/${f.subject}`;
}

export function createSinks(configs: SinkConfig[], defaultMinSeverity: Severity): Sink[] {
    return configs.map((config) => {
        const minSeverity = config.minSeverity ?? defaultMinSeverity;
        switch (config.type) {
            case 'console':
                return { name: 'console', minSeverity, send: async (f) => console.log(formatConsole(f)) };
            case 'discord':
                return { name: 'discord', minSeverity, send: (f) => postJson(config.url, discordPayload(f)) };
            case 'slack':
                return { name: 'slack', minSeverity, send: (f) => postJson(config.url, slackPayload(f)) };
            case 'telegram':
                return {
                    name: 'telegram',
                    minSeverity,
                    send: (f) =>
                        postJson(`https://api.telegram.org/bot${config.botToken}/sendMessage`, {
                            chat_id: config.chatId,
                            text: plainText(f),
                            disable_web_page_preview: true,
                        }),
                };
            case 'webhook':
                return { name: 'webhook', minSeverity, send: (f) => postJson(config.url, f, config.headers) };
        }
    });
}

/** Returns false if any eligible sink failed. */
export async function dispatch(sinks: Sink[], finding: Finding): Promise<boolean> {
    const results = await Promise.allSettled(
        sinks
            .filter((sink) => severityRank(finding.severity) >= severityRank(sink.minSeverity))
            .map((sink) => sink.send(finding).catch((error: Error) => Promise.reject(new Error(`${sink.name}: ${error.message}`)))),
    );
    let delivered = true;
    for (const result of results) {
        if (result.status === 'fulfilled') continue;
        delivered = false;
        console.error(pc.red(`Alert delivery failed, will retry on next start: ${(result.reason as Error).message}`));
    }
    return delivered;
}

function formatConsole(f: Finding): string {
    const when = f.blockTime ? new Date(f.blockTime * 1000).toISOString() : `slot ${f.slot}`;
    const lines = [
        `${SEVERITY_COLOR[f.severity](` ${f.severity.toUpperCase()} `)} ${pc.bold(f.title)} ${pc.dim(`· ${f.subjectLabel} · ${when}`)}`,
        `  ${f.description}`,
        ...Object.entries(f.details).map(([k, v]) => `  ${pc.dim(`${k}:`)} ${v}`),
        `  ${pc.dim(findingUrl(f))}`,
    ];
    return lines.join('\n');
}

function plainText(f: Finding): string {
    const text = [
        `${SEVERITY_EMOJI[f.severity]} ${f.severity.toUpperCase()}: ${f.title}`,
        f.subjectLabel,
        f.description,
        ...Object.entries(f.details).map(([k, v]) => `${k}: ${v}`),
    ].join('\n');
    return `${clip(text, TELEGRAM_MAX_TEXT - 140)}\n${findingUrl(f)}\nPowered by Helius`;
}

/** Discord embed limits: title 256, description 4096, 25 fields of name 256 / value 1024 (non-empty), 6000 total. */
function discordPayload(f: Finding): unknown {
    return {
        username: 'Watchtower',
        embeds: [
            {
                title: clip(`${SEVERITY_EMOJI[f.severity]} ${f.title}`, 256),
                description: clip(f.description, 2000),
                url: findingUrl(f),
                color: SEVERITY_HEX[f.severity],
                fields: [
                    { name: 'Subject', value: `${f.subjectLabel}\n\`${f.subject}\``, inline: false },
                    ...Object.entries(f.details).map(([name, value]) => ({
                        name: clip(name, 256),
                        value: clip(value || '—', 300),
                        inline: false,
                    })),
                ].slice(0, 12),
                footer: {
                    text: `Powered by Helius · ${f.severity.toUpperCase()} · ${f.detector} · slot ${f.slot}`,
                    icon_url: HELIUS_ICON_URL,
                },
                timestamp: f.blockTime ? new Date(f.blockTime * 1000).toISOString() : undefined,
            },
        ],
    };
}

/** Slack limits: header 150, section text 3000, 10 fields of 2000. `&`, `<`, `>` must be escaped in mrkdwn. */
function slackPayload(f: Finding): unknown {
    const fields = Object.entries(f.details)
        .slice(0, 10)
        .map(([k, v]) => ({ type: 'mrkdwn', text: clip(`*${slackEscape(k)}*\n${slackEscape(v)}`, 2000) }));
    return {
        text: `${SEVERITY_EMOJI[f.severity]} ${f.title}: ${f.subjectLabel}`,
        blocks: [
            { type: 'header', text: { type: 'plain_text', text: clip(`${SEVERITY_EMOJI[f.severity]} ${f.title}`, 150) } },
            {
                type: 'section',
                text: { type: 'mrkdwn', text: clip(`*${slackEscape(f.subjectLabel)}*\n${slackEscape(f.description)}`, 3000) },
            },
            ...(fields.length > 0 ? [{ type: 'section', fields }] : []),
            {
                type: 'context',
                elements: [
                    { type: 'image', image_url: HELIUS_ICON_URL, alt_text: 'Helius' },
                    { type: 'mrkdwn', text: `Powered by Helius · ${f.severity.toUpperCase()} · <${findingUrl(f)}|View on Orb>` },
                ],
            },
        ],
    };
}

const TELEGRAM_MAX_TEXT = 4096;

function clip(text: string, max: number): string {
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function slackEscape(text: string): string {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const MAX_RATE_LIMIT_RETRIES = 3;

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}, attempt = 0): Promise<void> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
        const retryAfterSeconds = Number(response.headers.get('retry-after')) || 2 ** attempt;
        await new Promise((resolve) => setTimeout(resolve, Math.min(retryAfterSeconds, 30) * 1000));
        return postJson(url, body, headers, attempt + 1);
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
}
