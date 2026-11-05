import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadEnvFile } from '../src/config.js';
import { assertSafeBinding, WatchtowerServer, type ServerOptions } from '../src/server/index.js';

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
    while (closers.length) await closers.pop()!();
});

async function start(overrides: Partial<ServerOptions> = {}, dir = mkdtempSync(join(tmpdir(), 'watchtower-server-'))): Promise<string> {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = new WatchtowerServer({
        host: '127.0.0.1',
        port: 0,
        configPath: join(dir, 'watchtower.yaml'),
        backfill: false,
        password: undefined,
        readOnly: false,
        ...overrides,
    });
    const { url, close } = await server.listen();
    closers.push(close);
    return url;
}

const post = (url: string, headers: Record<string, string> = { 'content-type': 'application/json' }) =>
    fetch(url, { method: 'POST', headers, body: '{}' });

describe('dashboard server', () => {
    it('serves the UI and an unconfigured state without secrets', async () => {
        const url = await start();
        expect((await fetch(url)).headers.get('content-type')).toContain('text/html');
        const state = await (await fetch(`${url}/api/state`)).json();
        expect(state).toMatchObject({ configured: false, readOnly: false, findings: [] });
        expect((await fetch(`${url}/brand/helius.svg`)).headers.get('content-type')).toBe('image/svg+xml');
    });

    it('refuses to be framed by another site', async () => {
        const url = await start();
        const res = await fetch(url);
        expect(res.headers.get('content-security-policy')).toBe("frame-ancestors 'none'");
        expect(res.headers.get('x-frame-options')).toBe('DENY');
        expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('rejects writes that a cross-site page could send', async () => {
        const url = await start();
        expect((await post(`${url}/api/config`, { 'content-type': 'text/plain' })).status).toBe(415);
        expect((await post(`${url}/api/config`, { 'content-type': 'application/json', origin: 'https://evil.example' })).status).toBe(415);
    });

    it('rejects a foreign Host header on loopback, defeating DNS rebinding', async () => {
        const url = await start();
        const status = await new Promise<number>((resolve) => {
            request(`${url}/api/state`, { headers: { host: 'evil.example' } }, (res) => resolve(res.statusCode ?? 0)).end();
        });
        expect(status).toBe(421);
    });

    it('requires the password when one is set', async () => {
        const url = await start({ password: 'hunter2hunter2' });
        expect((await fetch(`${url}/api/state`)).status).toBe(401);
        const auth = { authorization: `Basic ${Buffer.from('any:hunter2hunter2').toString('base64')}` };
        expect((await fetch(`${url}/api/state`, { headers: auth })).status).toBe(200);
    });

    it('refuses every write in read-only mode and hides the config', async () => {
        const url = await start({ readOnly: true });
        expect((await post(`${url}/api/config`)).status).toBe(403);
        expect((await (await fetch(`${url}/api/state`)).json()).config).toBeNull();
    });

    it('does not serve files outside the UI directory', async () => {
        const url = await start();
        expect((await fetch(`${url}/..%2F..%2Fpackage.json`)).status).toBe(404);
        expect((await fetch(`${url}/server.ts`)).status).toBe(404);
    });

    it('refuses to bind a public interface without a password or read-only mode', () => {
        expect(() => assertSafeBinding({ host: '0.0.0.0', password: undefined, readOnly: false })).toThrow(/Refusing/);
        expect(() => assertSafeBinding({ host: '0.0.0.0', password: 'x', readOnly: false })).not.toThrow();
        expect(() => assertSafeBinding({ host: '0.0.0.0', password: undefined, readOnly: true })).not.toThrow();
    });
});

describe('.env loading', () => {
    it('picks up edits to .env on reload', () => {
        const path = join(mkdtempSync(join(tmpdir(), 'watchtower-env-')), '.env');
        writeFileSync(path, 'WATCHTOWER_TEST_RELOAD=first\n');
        loadEnvFile(path);
        expect(process.env.WATCHTOWER_TEST_RELOAD).toBe('first');
        writeFileSync(path, 'WATCHTOWER_TEST_RELOAD=second\n');
        loadEnvFile(path);
        expect(process.env.WATCHTOWER_TEST_RELOAD).toBe('second');
        delete process.env.WATCHTOWER_TEST_RELOAD;
    });
});

describe('pause and resume', () => {
    it('reports not paused when nothing is configured, and refuses both in read-only mode', async () => {
        const url = await start();
        const paused = await (await post(`${url}/api/pause`)).json();
        expect(paused).toMatchObject({ paused: false, configured: false });
        const resumed = await (await post(`${url}/api/resume`)).json();
        expect(resumed).toMatchObject({ paused: false });

        const readOnly = await start({ readOnly: true });
        expect((await post(`${readOnly}/api/pause`)).status).toBe(403);
        expect((await post(`${readOnly}/api/resume`)).status).toBe(403);
    });
});

describe('monitors', () => {
    const send = (url: string, path: string, body: unknown) =>
        fetch(`${url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

    it('creates monitors with their own config and state file, and lists them', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'watchtower-server-'));
        const url = await start({}, dir);
        const created = await (await send(url, '/api/monitors', { name: 'Kamino Lend' })).json();
        expect(created.monitor).toBe('kamino-lend');
        expect(created.configured).toBe(false);
        expect(readFileSync(join(dir, 'monitors', 'kamino-lend.yaml'), 'utf8')).toContain('stateFile: .watchtower/kamino-lend.json');

        const again = await (await send(url, '/api/monitors', { name: 'Kamino Lend' })).json();
        expect(again.monitor).toBe('kamino-lend-2');
        expect(again.monitors.map((m: { id: string; name: string; phase: string }) => [m.id, m.name, m.phase])).toEqual([
            ['default', 'New monitor', 'unconfigured'],
            ['kamino-lend', 'Kamino Lend', 'unconfigured'],
            ['kamino-lend-2', 'Kamino Lend', 'unconfigured'],
        ]);
        expect((await (await fetch(`${url}/api/state?monitor=kamino-lend`)).json()).monitor).toBe('kamino-lend');
    });

    it('deletes a monitor that is not running, and refuses unknown ones', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'watchtower-server-'));
        const url = await start({}, dir);
        await send(url, '/api/monitors', { name: 'Drift' });
        const res = await send(url, '/api/monitors/delete', { monitor: 'drift' });
        expect((await res.json()).monitors.map((m: { id: string }) => m.id)).toEqual(['default']);
        expect(existsSync(join(dir, 'monitors', 'drift.yaml'))).toBe(false);
        expect((await send(url, '/api/monitors/delete', { monitor: 'drift' })).status).toBe(400);
        expect((await send(url, '/api/monitors', { name: '  ' })).status).toBe(400);
    });

    it('picks up monitors saved in the monitors folder', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'watchtower-server-'));
        writeFileSync(join(dir, 'watchtower.yaml'), 'name: Pump AMM\n');
        mkdirSync(join(dir, 'monitors'));
        writeFileSync(join(dir, 'monitors', 'jupiter.yaml'), 'name: Jupiter\n');
        const url = await start({}, dir);
        const state = await (await fetch(`${url}/api/state`)).json();
        expect(state.monitors.map((m: { id: string; name: string }) => [m.id, m.name])).toEqual([
            ['default', 'Pump AMM'],
            ['jupiter', 'Jupiter'],
        ]);
    });
});
