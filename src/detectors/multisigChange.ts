import type { Severity } from '../config.js';
import { PROGRAMS, SQUADS_PROGRAMS } from '../constants.js';
import { account, arg, field, nameOf, parentOf, type ParsedInstruction, type ParsedTx } from '../model.js';
import { maxSeverity } from './severity.js';
import { findingFor, type Detector, type DetectorContext, type Finding } from './types.js';

const ID = 'multisig-change';

type Rule = { severity: Severity; title: string };

/** Squads v4 instructions a config authority signs alone, without a member vote. */
const AUTHORITY_CHANGES = new Map<string, Rule>([
    ['multisigaddmember', { severity: 'high', title: 'Member added by config authority' }],
    ['multisigremovemember', { severity: 'high', title: 'Member removed by config authority' }],
    ['multisigchangethreshold', { severity: 'high', title: 'Threshold changed by config authority' }],
    ['multisigsettimelock', { severity: 'high', title: 'Time lock changed by config authority' }],
    ['multisigsetconfigauthority', { severity: 'critical', title: 'Config authority changed' }],
    ['multisigsetrentcollector', { severity: 'medium', title: 'Rent collector changed by config authority' }],
    ['multisigaddspendinglimit', { severity: 'high', title: 'Spending limit added by config authority' }],
    ['multisigremovespendinglimit', { severity: 'medium', title: 'Spending limit removed by config authority' }],
]);

/** v3 config instructions, invoked by CPI from an approved `executeTransaction`. */
const V3_CONFIG_CHANGES = new Map<string, Rule>([
    ['addmember', { severity: 'high', title: 'Member added' }],
    ['removemember', { severity: 'high', title: 'Member removed' }],
    ['changethreshold', { severity: 'high', title: 'Threshold changed' }],
    ['addmemberandchangethreshold', { severity: 'high', title: 'Member added and threshold changed' }],
    ['removememberandchangethreshold', { severity: 'high', title: 'Member removed and threshold changed' }],
    ['addauthority', { severity: 'medium', title: 'Vault authority added' }],
    ['setexternalexecute', { severity: 'medium', title: 'External execute setting changed' }],
]);

/** Proposal contents and vault executions are reported by `multisig-proposal`. */
const ACTIVITY = new Map<string, Rule>([
    ['batchexecutetransaction', { severity: 'medium', title: 'Batch transaction executed' }],
    ['spendinglimituse', { severity: 'medium', title: 'Spending limit used' }],
    ['proposalcreate', { severity: 'info', title: 'Proposal created' }],
    ['proposalapprove', { severity: 'info', title: 'Proposal approved' }],
    ['proposalreject', { severity: 'info', title: 'Proposal rejected' }],
    ['proposalcancel', { severity: 'info', title: 'Proposal cancelled' }],
    ['proposalcancelv2', { severity: 'info', title: 'Proposal cancelled' }],
    ['createtransaction', { severity: 'low', title: 'Transaction proposed' }],
    ['approvetransaction', { severity: 'info', title: 'Transaction approved' }],
    ['rejecttransaction', { severity: 'info', title: 'Transaction rejected' }],
    ['canceltransaction', { severity: 'info', title: 'Transaction cancelled' }],
]);

export const multisigChange: Detector = {
    id: ID,
    description: 'Squads membership, threshold, time lock and config changes, plus vault executions',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            if (!SQUADS_PROGRAMS.includes(ix.programId)) continue;
            const multisig = account(ix, 'multisig')?.pubkey;
            const watched = multisig ? ctx.targets.multisigs.get(multisig) : undefined;
            const name = nameOf(ix);
            if (!watched || !name) continue;

            const base = { subject: watched.address, subjectLabel: watched.label };
            const add = (severity: Severity, title: string, description: string, details: Record<string, string>) =>
                findings.push(findingFor(ID, tx, ix, { ...base, severity, title, description, details }));

            if (name === 'configtransactioncreate') {
                const actions = configActions(ix);
                const severity = maxSeverity('medium', ...actions.map((a) => a.severity));
                const transaction = account(ix, 'transaction')?.pubkey;
                if (transaction) {
                    ctx.state.rememberConfigTransaction(transaction, {
                        multisig: watched.address,
                        actions: actions.map((a) => a.text),
                        severity,
                        signature: tx.signature,
                        slot: tx.slot,
                    });
                }
                add(
                    severity,
                    'Config change proposed',
                    `A proposal to change ${watched.label}: ${actions.map((a) => a.text).join('; ') || 'unknown actions'}.`,
                    withCommon(tx, ix, { 'Config transaction': transaction ?? 'unknown' }),
                );
                continue;
            }

            if (name === 'configtransactionexecute') {
                const transaction = account(ix, 'transaction')?.pubkey;
                const proposed = transaction ? ctx.state.configTransaction(transaction) : undefined;
                const summary = proposed?.actions.join('; ');
                add(
                    maxSeverity('high', proposed?.severity ?? 'high'),
                    'Config change executed',
                    summary
                        ? `${watched.label} now has: ${summary}.`
                        : `A config transaction on ${watched.label} was executed. Its proposal predates the scanned history.`,
                    withCommon(tx, ix, {
                        'Config transaction': transaction ?? 'unknown',
                        ...(proposed ? { 'Proposed in': proposed.signature } : {}),
                    }),
                );
                continue;
            }

            const v3Change = ix.programId === PROGRAMS.squadsV3 ? V3_CONFIG_CHANGES.get(name) : undefined;
            if (v3Change) {
                const change = describeV3Change(ix);
                add(
                    maxSeverity(v3Change.severity, change.severity),
                    v3Change.title,
                    `${watched.label} was changed after a member vote: ${change.text}.`,
                    withCommon(tx, parentOf(tx, ix) ?? ix, {}),
                );
                continue;
            }

            const authorityChange = ix.programId === PROGRAMS.squadsV4 ? AUTHORITY_CHANGES.get(name) : undefined;
            if (authorityChange) {
                add(
                    authorityChange.severity,
                    authorityChange.title,
                    `${watched.label} was changed directly by its config authority, without a member vote: ${describeDirectChange(name, ix)}.`,
                    withCommon(tx, ix, {}),
                );
                continue;
            }

            const activity = ACTIVITY.get(name);
            if (activity) {
                add(activity.severity, activity.title, `${activity.title} on ${watched.label}.`, withCommon(tx, ix, {}));
            }
        }
        return findings;
    },
};

interface ConfigAction {
    text: string;
    severity: Severity;
}

/** Renders `args.actions`, decoded as `[{ "SetTimeLock": { "new_time_lock": 86400 } }, ...]`. */
function configActions(ix: ParsedInstruction): ConfigAction[] {
    const inner = arg(ix, 'args') as Record<string, unknown> | undefined;
    const actions = (field(inner, 'actions') ?? arg(ix, 'actions')) as unknown[] | undefined;
    if (!Array.isArray(actions)) return [];
    return actions.map(describeAction);
}

function describeAction(action: unknown): ConfigAction {
    if (typeof action === 'string') return { text: action, severity: 'medium' };
    const [variant, fields] = Object.entries((action ?? {}) as Record<string, Record<string, unknown>>)[0] ?? [];
    const f = fields ?? {};
    switch (variant) {
        case 'AddMember': {
            const member = field(f, 'newMember');
            const mask = field(field(member, 'permissions'), 'mask') as number | undefined;
            return {
                text: `add member ${String(field(member, 'key') ?? '?')} (${permissionsText(mask)})`,
                severity: 'high',
            };
        }
        case 'RemoveMember':
            return { text: `remove member ${String(field(f, 'oldMember'))}`, severity: 'high' };
        case 'ChangeThreshold':
            return {
                text: `threshold → ${String(field(f, 'newThreshold'))}`,
                severity: Number(field(f, 'newThreshold')) <= 1 ? 'critical' : 'high',
            };
        case 'SetTimeLock':
            return {
                text: `time lock → ${String(field(f, 'newTimeLock'))}s`,
                severity: Number(field(f, 'newTimeLock')) === 0 ? 'high' : 'medium',
            };
        case 'AddSpendingLimit':
            return {
                text: `add spending limit of ${String(field(f, 'amount'))} (mint ${String(field(f, 'mint'))}) for ${(field(f, 'members') as string[] | undefined)?.join(', ') ?? 'unknown members'}`,
                severity: 'high',
            };
        case 'RemoveSpendingLimit':
            return { text: `remove spending limit ${String(field(f, 'spendingLimit'))}`, severity: 'medium' };
        case 'SetRentCollector':
            return { text: `rent collector → ${String(field(f, 'newRentCollector'))}`, severity: 'medium' };
        default:
            return { text: `${variant ?? 'unknown'} ${JSON.stringify(f)}`, severity: 'medium' };
    }
}

function describeDirectChange(name: string, ix: ParsedInstruction): string {
    const inner = (arg(ix, 'args') as Record<string, unknown> | undefined) ?? ix.args ?? {};
    switch (name) {
        case 'multisigaddmember':
            return describeAction({ AddMember: inner }).text;
        case 'multisigremovemember':
            return describeAction({ RemoveMember: inner }).text;
        case 'multisigchangethreshold':
            return describeAction({ ChangeThreshold: inner }).text;
        case 'multisigsettimelock':
            return describeAction({ SetTimeLock: { newTimeLock: field(inner, 'timeLock', 'newTimeLock') } }).text;
        case 'multisigsetconfigauthority':
            return `config authority → ${String(field(inner, 'configAuthority'))}`;
        default:
            return JSON.stringify(inner);
    }
}

function describeV3Change(ix: ParsedInstruction): ConfigAction {
    const parts: ConfigAction[] = [];
    const newMember = arg(ix, 'newMember');
    const oldMember = arg(ix, 'oldMember');
    const newThreshold = arg(ix, 'newThreshold');
    if (newMember !== undefined) parts.push({ text: `add member ${String(newMember)}`, severity: 'high' });
    if (oldMember !== undefined) parts.push({ text: `remove member ${String(oldMember)}`, severity: 'high' });
    if (newThreshold !== undefined) parts.push(describeAction({ ChangeThreshold: { newThreshold } }));
    if (parts.length === 0) return { text: ix.instructionName ?? 'config change', severity: 'medium' };
    return {
        text: parts.map((p) => p.text).join(', '),
        severity: maxSeverity(...parts.map((p) => p.severity)),
    };
}

function permissionsText(mask: number | undefined): string {
    if (mask === undefined) return 'unknown permissions';
    const parts = [mask & 1 ? 'initiate' : '', mask & 2 ? 'vote' : '', mask & 4 ? 'execute' : ''].filter(Boolean);
    return parts.join('/') || 'no permissions';
}

function withCommon(tx: ParsedTx, ix: ParsedInstruction, details: Record<string, string>): Record<string, string> {
    const signer = ix.accounts?.find((a) => a.isSigner && a.pubkey !== tx.feePayer)?.pubkey ?? tx.feePayer;
    return { ...details, ...(signer ? { Signer: signer } : {}) };
}
