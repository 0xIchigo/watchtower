import { describe, expect, it, vi } from 'vitest';
import { PROGRAMS } from '../src/constants.js';
import { detect } from '../src/detectors/index.js';
import { formatAmount } from '../src/format.js';
import { Engine } from '../src/engine.js';
import type { Sink } from '../src/sinks.js';
import { context, KEYS, loaderUpgrade, tx } from './helpers.js';

describe('program-deployment', () => {
    it('flags an upgrade executed through a Squads v3 multisig', () => {
        const findings = detect(
            tx('sig-upgrade', 100, [
                {
                    programId: PROGRAMS.squadsV3,
                    name: 'executeTransaction',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['member', KEYS.member, true],
                    ],
                    inner: [loaderUpgrade],
                },
            ]),
            context(),
        );
        expect(findings.map((f) => f.title).sort()).toEqual(['Multisig proposal executed', 'Program upgraded']);
        const upgrade = findings.find((f) => f.detector === 'program-deployment')!;
        expect(upgrade).toMatchObject({ severity: 'high', subject: KEYS.program });
        expect(upgrade.details['Executed via']).toBe(`Squads multisig ${KEYS.multisig}`);
        expect(upgrade.details.Buffer).toBe(KEYS.buffer);
    });

    it('flags a direct upgrade as signed without a multisig', () => {
        const [finding] = detect(tx('sig-direct', 100, [loaderUpgrade]), context());
        expect(finding!.details['Executed via']).toBe('Direct signature (no multisig)');
    });

    it('treats an upgrade-authority transfer as critical', () => {
        const [finding] = detect(
            tx('sig-auth', 100, [
                {
                    programId: PROGRAMS.bpfLoaderUpgradeable,
                    name: 'set_authority',
                    accounts: [
                        ['target_account', KEYS.programData],
                        ['current_authority', KEYS.vault, true],
                        ['new_authority', KEYS.attacker],
                    ],
                },
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'critical', title: 'Upgrade authority changed' });
        expect(finding!.details['New authority']).toBe(KEYS.attacker);
    });

    it('reports a program made immutable when no new authority is given', () => {
        const [finding] = detect(
            tx('sig-immutable', 100, [
                {
                    programId: PROGRAMS.bpfLoaderUpgradeable,
                    name: 'set_authority',
                    accounts: [
                        ['target_account', KEYS.programData],
                        ['current_authority', KEYS.vault, true],
                    ],
                },
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'high', title: 'Program made immutable' });
    });

    it('ignores loader activity on other programs', () => {
        const other = {
            ...loaderUpgrade,
            accounts: [['program_account', 'SomeOtherProgram111111111111111111111111111']] as [string, string][],
        };
        expect(detect(tx('sig-other', 100, [other]), context())).toEqual([]);
    });
});

describe('multisig-change', () => {
    it('links a v4 config execution back to the proposal that described it', () => {
        const ctx = context();
        const proposed = detect(
            tx('sig-propose', 100, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'configTransactionCreate',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['transaction', KEYS.configTx],
                        ['creator', KEYS.member, true],
                    ],
                    args: {
                        args: {
                            actions: [{ ChangeThreshold: { newThreshold: 1 } }, { SetTimeLock: { newTimeLock: 0 } }],
                            memo: null,
                        },
                    },
                },
            ]),
            ctx,
        );
        expect(proposed[0]).toMatchObject({ severity: 'critical', title: 'Config change proposed' });
        expect(proposed[0]!.description).toContain('threshold → 1');

        const executed = detect(
            tx('sig-execute', 200, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'configTransactionExecute',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['transaction', KEYS.configTx],
                        ['member', KEYS.member, true],
                    ],
                },
            ]),
            ctx,
        );
        expect(executed[0]).toMatchObject({ severity: 'critical', title: 'Config change executed' });
        expect(executed[0]!.description).toContain('time lock → 0s');
        expect(executed[0]!.details['Proposed in']).toBe('sig-propose');
    });

    it('treats a direct config-authority change on a controlled v4 multisig as unvoted', () => {
        const [finding] = detect(
            tx('sig-direct-member', 100, [
                {
                    programId: PROGRAMS.squadsV4,
                    name: 'multisigAddMember',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['configAuthority', KEYS.attacker, true],
                    ],
                    args: { args: { newMember: { key: KEYS.attacker, permissions: { mask: 7 } }, memo: null } },
                },
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'high', title: 'Member added by config authority' });
        expect(finding!.description).toContain('without a member vote');
        expect(finding!.description).toContain('initiate/vote/execute');
    });

    it('reads v3 config changes executed by CPI', () => {
        const findings = detect(
            tx('sig-v3', 100, [
                {
                    programId: PROGRAMS.squadsV3,
                    name: 'executeTransaction',
                    accounts: [
                        ['multisig', KEYS.multisig],
                        ['member', KEYS.member, true],
                    ],
                    inner: [
                        {
                            programId: PROGRAMS.squadsV3,
                            name: 'removeMemberAndChangeThreshold',
                            accounts: [['multisig', KEYS.multisig, true]],
                            args: { oldMember: KEYS.member, newThreshold: 1 },
                        },
                    ],
                },
            ]),
            context(),
        );
        const change = findings.find((f) => f.title === 'Member removed and threshold changed');
        expect(change).toMatchObject({ severity: 'critical' });
        expect(change!.description).toContain(`remove member ${KEYS.member}`);
    });
});

describe('mint-authority', () => {
    it('flags a mint authority handover', () => {
        const [finding] = detect(
            tx('sig-mint-auth', 100, [
                {
                    programId: PROGRAMS.splToken,
                    name: 'set_authority',
                    accounts: [
                        ['mint_or_account', KEYS.mint],
                        ['current_authority', KEYS.member, true],
                    ],
                    args: { authority_type: 'mintTokens', new_authority: KEYS.attacker },
                },
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'critical', title: 'mintTokens authority changed' });
    });

    it('flags a mint of at least 1% of supply as large', () => {
        const [finding] = detect(
            tx('sig-mint', 100, [
                {
                    programId: PROGRAMS.splToken,
                    name: 'mint_to',
                    accounts: [
                        ['mint', KEYS.mint],
                        ['destination_account', KEYS.attacker],
                        ['mint_authority', KEYS.member, true],
                    ],
                    args: { amount: '50000000' },
                },
            ]),
            context({ mintSupply: 1_000_000_000n }),
        );
        expect(finding).toMatchObject({ severity: 'high', title: 'Large mint' });
    });

    it('flags a Token-2022 transfer hook change by its parser-v2 name', () => {
        const [finding] = detect(
            tx('sig-hook', 100, [
                {
                    programId: PROGRAMS.token2022,
                    name: 'transfer_hook_extension.update',
                    accounts: [
                        ['mint', KEYS.mint],
                        ['authority', KEYS.member, true],
                    ],
                    args: { program_id: KEYS.attacker },
                },
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'critical', title: 'Transfer hook program changed' });
    });
});

describe('mint amounts', () => {
    it('formats raw amounts with their decimals', () => {
        expect(formatAmount(1_500_000n, 6)).toBe('1.5');
        expect(formatAmount(12_345_000_000n, 6)).toBe('12,345');
        expect(formatAmount(7n, 0)).toBe('7');
    });

    it('ignores set_authority on a token account of the mint', () => {
        const findings = detect(
            tx('sig-token-account', 100, [
                {
                    programId: PROGRAMS.splToken,
                    name: 'set_authority',
                    accounts: [
                        ['mint_or_account', KEYS.buffer],
                        ['current_authority', KEYS.member, true],
                        ['mint', KEYS.mint],
                    ],
                    args: { authority_type: 'accountOwner', new_authority: KEYS.attacker },
                },
            ]),
            context(),
        );
        expect(findings).toEqual([]);
    });
});

describe('privileged-instruction', () => {
    const adminCall = (signature: string, signer: string, name = 'withdraw_protocol_fee', accounts: [string, string, boolean?][] = []) =>
        tx(signature, 100, [{ programId: KEYS.program, name, accounts: [['admin', signer, true], ...accounts], args: {} }]);

    it('alerts on admin calls and escalates for a signer outside the baseline', () => {
        const ctx = context({ privileged: ['withdrawProtocolFee'] });
        expect(detect(adminCall('sig-1', KEYS.member), ctx)[0]).toMatchObject({ severity: 'medium' });
        expect(detect(adminCall('sig-2', KEYS.member), ctx)[0]).toMatchObject({ severity: 'medium' });
        expect(detect(adminCall('sig-3', KEYS.attacker), ctx)[0]).toMatchObject({
            severity: 'high',
            title: 'New signer on withdraw_protocol_fee',
            stages: ['control'],
        });
        expect([...ctx.state.adminKeys(KEYS.program).keys()]).toEqual([KEYS.member, KEYS.attacker]);
    });

    it('classifies admin hand-offs, listings, oracle and risk changes', () => {
        const ctx = context({ privileged: ['setAdmin', 'initializeSpotMarket', 'updateOracle', 'updateWithdrawLimit'] });
        detect(adminCall('sig-base', KEYS.member, 'update_withdraw_limit'), ctx);
        const call = (sig: string, name: string, accounts: [string, string, boolean?][] = []) =>
            detect(adminCall(sig, KEYS.member, name, accounts), ctx)[0]!;
        expect(call('sig-a', 'set_admin')).toMatchObject({
            severity: 'high',
            title: 'Admin control changed: set_admin',
            stages: ['control'],
        });
        const listing = call('sig-l', 'initialize_spot_market', [['spot_market_mint', KEYS.mint]]);
        expect(listing).toMatchObject({ severity: 'high', title: 'New market or asset added: initialize_spot_market', stages: ['risk'] });
        expect(listing.details['Listed mint']).toBe(KEYS.mint);
        expect(call('sig-o', 'update_oracle')).toMatchObject({ severity: 'high', stages: ['risk'] });
        expect(call('sig-r', 'update_withdraw_limit')).toMatchObject({
            severity: 'medium',
            title: 'Risk setting changed: update_withdraw_limit',
            stages: ['risk'],
        });
    });
});

describe('durable nonce escalation', () => {
    it('raises severity when a privileged action rides a durable nonce', () => {
        const [finding] = detect(
            tx('sig-nonce', 100, [
                {
                    programId: PROGRAMS.system,
                    name: 'advance_nonce_account',
                    accounts: [
                        ['nonce_account', KEYS.buffer],
                        ['nonce_authority', KEYS.member, true],
                    ],
                },
                loaderUpgrade,
            ]),
            context(),
        );
        expect(finding).toMatchObject({ severity: 'critical', title: 'Program upgraded' });
        expect(finding!.details['Durable nonce']).toMatch(/signed long before/);
    });
});

describe('engine', () => {
    const silent = () => 'silent' as const;

    it('reports a transaction once even when backfill and the stream both deliver it', async () => {
        const engine = new Engine(context(), []);
        const upgrade = tx('sig-dup', 100, [loaderUpgrade]);
        expect(await engine.process(upgrade, silent)).toHaveLength(1);
        expect(await engine.process({ ...upgrade, source: 'backfill' }, silent)).toHaveLength(0);
    });

    it('skips failed transactions', async () => {
        const engine = new Engine(context(), []);
        const failed = { ...tx('sig-failed', 100, [loaderUpgrade]), succeeded: false };
        expect(await engine.process(failed, silent)).toEqual([]);
    });

    it('sends, queues or records silently by alert mode', async () => {
        const sent: string[] = [];
        const ctx = context();
        const engine = new Engine(ctx, [recordingSink(sent)]);
        await engine.process(tx('sig-send', 100, [loaderUpgrade]), () => 'send');
        await engine.process(tx('sig-queue', 101, [loaderUpgrade]), () => 'queue');
        await engine.process(tx('sig-silent', 102, [loaderUpgrade]), silent);
        await engine.idle();
        expect(sent).toEqual(['sig-send']);
        expect(ctx.state.pendingAlerts().map((f) => f.signature)).toEqual(['sig-queue']);

        expect(await engine.flushPendingAlerts()).toBe(1);
        expect(sent).toEqual(['sig-send', 'sig-queue']);
        expect(ctx.state.pendingAlerts()).toEqual([]);
    });

    it('keeps an alert queued when a sink fails', async () => {
        const ctx = context();
        const failing: Sink = { name: 'failing', minSeverity: 'info', send: () => Promise.reject(new Error('HTTP 500')) };
        const engine = new Engine(ctx, [failing]);
        vi.spyOn(console, 'error').mockImplementation(() => {});
        await engine.process(tx('sig-retry', 100, [loaderUpgrade]), () => 'send');
        await engine.idle();
        expect(ctx.state.pendingAlerts().map((f) => f.signature)).toEqual(['sig-retry']);
    });

    it('records without waiting on a slow channel, then delivers the most severe alerts first', async () => {
        const ctx = context({ privileged: ['withdrawProtocolFee'] });
        const sent: string[] = [];
        let release: () => void = () => {};
        const gate = new Promise<void>((resolve) => (release = resolve));
        const slow: Sink = {
            name: 'slow',
            minSeverity: 'info',
            send: async (finding) => {
                await gate;
                sent.push(finding.severity);
            },
        };
        const engine = new Engine(ctx, [slow]);
        const admin = (sig: string) =>
            tx(sig, 100, [{ programId: KEYS.program, name: 'withdraw_protocol_fee', accounts: [['admin', KEYS.member, true]] }]);
        await engine.process(admin('sig-a'), () => 'send');
        await engine.process(admin('sig-b'), () => 'send');
        await engine.process(
            tx('sig-c', 101, [
                {
                    programId: PROGRAMS.bpfLoaderUpgradeable,
                    name: 'close',
                    accounts: [
                        ['program_data_account', KEYS.programData],
                        ['program_account', KEYS.program],
                    ],
                },
            ]),
            () => 'send',
        );
        expect(ctx.state.findings()).toHaveLength(3);
        expect(sent).toEqual([]);
        release();
        await engine.idle();
        expect(sent).toEqual(['medium', 'critical', 'medium']);
    });

    it('queues an alert before listeners run, so a failing listener cannot lose it', async () => {
        const ctx = context();
        const engine = new Engine(ctx, [], () => {
            throw new Error('listener failed');
        });
        await expect(engine.process(tx('sig-x', 100, [loaderUpgrade]), () => 'queue')).rejects.toThrow('listener failed');
        expect(ctx.state.pendingAlerts().map((f) => f.signature)).toEqual(['sig-x']);
    });
});

function recordingSink(sent: string[]): Sink {
    return {
        name: 'recording',
        minSeverity: 'info',
        send: async (finding) => {
            sent.push(finding.signature ?? finding.id);
        },
    };
}
