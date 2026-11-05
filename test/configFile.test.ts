import { describe, expect, it } from 'vitest';
import { fromBrowser, maskSecrets } from '../src/configFile.js';

const saved = {
    programs: [{ id: 'P' }],
    stateFile: '.watchtower/state.json',
    alerts: {
        sinks: [
            { type: 'discord', url: 'https://discord.com/api/webhooks/1/a' },
            { type: 'webhook', url: '${WEBHOOK_URL_1}', headers: { authorization: 'Bearer secret' } },
            { type: 'discord', url: 'https://discord.com/api/webhooks/2/c' },
        ],
    },
};

describe('configs from the browser', () => {
    it('masks literal secrets, including webhook headers, and leaves references as written', () => {
        const [a, b] = maskSecrets(saved).alerts!.sinks!;
        expect(a!.url).toMatch(/^••••••••[0-9a-f]{8}$/);
        expect(b!.url).toBe('${WEBHOOK_URL_1}');
        expect((b!.headers as Record<string, string>).authorization).toMatch(/^••••••••/);
        expect(JSON.stringify(maskSecrets(saved))).not.toContain('secret');
    });

    it('restores a masked secret to its own channel after another channel is removed', () => {
        const [, webhook, third] = maskSecrets(saved).alerts!.sinks!;
        const submitted = { ...saved, alerts: { sinks: [webhook!, third!, { type: 'slack', url: 'https://hooks.slack.com/x' }] } };
        const [w, c, s] = fromBrowser(submitted, saved).alerts!.sinks!;
        expect(w).toEqual(saved.alerts.sinks[1]);
        expect(c!.url).toBe('https://discord.com/api/webhooks/2/c');
        expect(s!.url).toBe('https://hooks.slack.com/x');
    });

    it('refuses environment references the saved config does not already have', () => {
        const header = {
            ...saved,
            alerts: { sinks: [{ type: 'webhook', url: 'https://example.com', headers: { x: '${HELIUS_API_KEY}' } }] },
        };
        expect(() => fromBrowser(header, saved)).toThrow('environment references');
        const name = { ...saved, programs: [{ id: 'P', name: '${HELIUS_API_KEY}' }] };
        expect(() => fromBrowser(name, saved)).toThrow('only allowed in alert channel secrets');
    });

    it('keeps the saved state file whatever the browser sends', () => {
        expect(fromBrowser({ ...saved, stateFile: '/etc/passwd' }, saved).stateFile).toBe('.watchtower/state.json');
        expect(fromBrowser({ programs: [{ id: 'P' }], stateFile: '/etc/passwd' }, null).stateFile).toBeUndefined();
    });
});
