import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { stringify } from 'yaml';
import { parseConfig, type FileConfig } from './config.js';

const ENV_REFERENCE = /^\$\{[A-Z0-9_]+\}$/;

const SECRET_FIELDS: Record<string, string[]> = {
    discord: ['url'],
    slack: ['url'],
    webhook: ['url'],
    telegram: ['botToken', 'chatId'],
};

type RawSink = Record<string, unknown>;
type RawConfig = Record<string, unknown> & { alerts?: { sinks?: RawSink[] } };

const MASK = '••••••••';
/** The hash suffix lets a masked secret be matched back to its channel without revealing it. */
const masked = (secret: string) => `${MASK}${createHash('sha256').update(secret).digest('hex').slice(0, 8)}`;

/**
 * Returns a copy of `sink` with every secret passed through `map`: the type's secret fields plus every
 * webhook header value. `name` is a stable label for the secret, such as `URL` or `HEADER_AUTHORIZATION`.
 */
export function mapSinkSecrets(sink: RawSink, map: (value: string, name: string) => string): RawSink {
    const copy = { ...sink };
    for (const field of SECRET_FIELDS[String(sink.type)] ?? []) {
        const value = sink[field];
        if (typeof value === 'string' && value !== '') copy[field] = map(value, field.replace(/[A-Z]/g, (c) => `_${c}`).toUpperCase());
    }
    if (sink.headers && typeof sink.headers === 'object') {
        copy.headers = Object.fromEntries(
            Object.entries(sink.headers as Record<string, unknown>).map(([header, value]) => [
                header,
                typeof value === 'string' && value !== ''
                    ? map(value, `HEADER_${header.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`)
                    : value,
            ]),
        );
    }
    return copy;
}

/** The saved config for the browser: literal sink secrets masked, `${VAR}` references as written. */
export function maskSecrets(saved: RawConfig): RawConfig {
    const sinks = saved.alerts?.sinks?.map((sink) => mapSinkSecrets(sink, (value) => (ENV_REFERENCE.test(value) ? value : masked(value))));
    return sinks ? { ...saved, alerts: { ...saved.alerts, sinks } } : saved;
}

/**
 * A config the browser submitted, made safe to save: masked secrets are restored from `saved` by hash, never
 * by position; `${VAR}` references are accepted only where `saved` already has them, so the browser cannot
 * read other variables; and `stateFile` keeps its saved value.
 */
export function fromBrowser(config: RawConfig, saved: RawConfig | null): RawConfig {
    const savedSecrets = new Map<string, string>();
    for (const sink of saved?.alerts?.sinks ?? []) {
        mapSinkSecrets(sink, (value) => (savedSecrets.set(ENV_REFERENCE.test(value) ? value : masked(value), value), value));
    }
    const { stateFile: _ignored, ...rest } = config;
    const sinks = config.alerts?.sinks?.map((sink) =>
        mapSinkSecrets(sink, (value) => {
            if (!value.startsWith(MASK) && !value.includes('${')) return value;
            const restored = savedSecrets.get(value);
            if (restored === undefined) {
                throw new Error(
                    'A channel secret must be entered in full; environment references and stale masked values are not accepted',
                );
            }
            return restored;
        }),
    );
    const document = { ...rest, ...(saved?.stateFile ? { stateFile: saved.stateFile } : {}), alerts: { ...config.alerts, sinks } };
    const withoutSecrets = { ...document, alerts: { ...config.alerts, sinks: sinks?.map((sink) => mapSinkSecrets(sink, () => '')) } };
    if (JSON.stringify(withoutSecrets).includes('${')) throw new Error('Environment references are only allowed in alert channel secrets');
    return document;
}

/** Validates and writes a config, moving literal sink secrets to `.env` and leaving `${VAR}` references in the YAML. */
export function saveConfig(path: string, raw: Record<string, unknown>): FileConfig {
    const secrets: Record<string, string> = {};
    const unusedName = (base: string) => {
        for (let n = 1; ; n++) {
            const name = `${base}_${n}`;
            if (process.env[name] === undefined && !Object.hasOwn(secrets, name)) return name;
        }
    };
    const sinks = ((raw.alerts as { sinks?: RawSink[] } | undefined)?.sinks ?? []).map((sink) =>
        mapSinkSecrets(sink, (value, name) => {
            if (ENV_REFERENCE.test(value)) return value;
            const variable = unusedName(`${String(sink.type).toUpperCase()}_${name}`);
            secrets[variable] = value;
            return `\${${variable}}`;
        }),
    );
    const document = { ...raw, alerts: { ...(raw.alerts as object | undefined), sinks } };

    for (const [key, value] of Object.entries(secrets)) process.env[key] = value;
    const parsed = parseConfig(document);
    writeEnv(secrets);
    writeFileSync(path, `# Managed by Watchtower. See watchtower.example.yaml for every option.\n${stringify(document)}`);
    return parsed;
}

/** Sets keys in `.env`, keeping every other line. */
export function writeEnv(values: Record<string, string>, path = '.env'): void {
    if (Object.keys(values).length === 0) return;
    const existing = existsSync(path) ? readFileSync(path, 'utf8').split('\n') : [];
    const kept = existing.filter((line) => {
        const key = line.split('=')[0]?.trim();
        return line.trim() !== '' && !(key && Object.hasOwn(values, key));
    });
    const added = Object.entries(values).map(([k, v]) => `${k}=${/[\s#"']/.test(v) ? JSON.stringify(v) : v}`);
    writeFileSync(path, `${[...kept, ...added].join('\n')}\n`, { mode: 0o600 });
}
