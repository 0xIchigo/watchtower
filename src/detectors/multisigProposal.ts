import { severityRank, type Severity } from '../config.js';
import { PROGRAMS, SQUADS_PROGRAMS } from '../constants.js';
import type { ProposedInstruction } from '../discover/squads.js';
import { formatAmount, humanDuration, short } from '../format.js';
import { account, nameOf, normalizeName, signers, type ParsedInstruction, type ParsedTx } from '../model.js';
import { usesDurableNonce } from './nonce.js';
import { escalate, maxSeverity } from './severity.js';
import { findingFor, type Detector, type DetectorContext, type Finding, type WatchedMultisig } from './types.js';
import { executionText, isWatchedLoaderChange, proposedInstructions, sameTransactionProposal } from './upgradeProposal.js';

const ID = 'multisig-proposal';
const FAST_EXECUTION_SECONDS = 3_600;

interface DescribedCall {
    text: string;
    severity: Severity;
}

export const multisigProposal: Detector = {
    id: ID,
    description: 'Every Squads proposal decoded, durable-nonce approvals, rushed executions and first-time proposers',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            if (!SQUADS_PROGRAMS.includes(ix.programId)) continue;
            const multisig = account(ix, 'multisig')?.pubkey;
            const watched = multisig ? ctx.targets.multisigs.get(multisig) : undefined;
            const name = nameOf(ix);
            if (!watched || !name) continue;

            const created = proposalCreated(tx, ix, name, watched, ctx);
            if (created) {
                findings.push(created);
                continue;
            }
            const approval = APPROVALS.get(name);
            if (approval && approval.programId === ix.programId && usesDurableNonce(tx)) {
                findings.push(nonceApproval(tx, ix, watched, approval.key, ctx));
                continue;
            }
            const execution = EXECUTIONS.get(name);
            if (execution && execution.programId === ix.programId) findings.push(executed(tx, ix, watched, execution.key, ctx));
        }
        return findings;
    },
};

/** `key` is the account role that identifies the approved proposal. */
const APPROVALS = new Map([
    ['proposalapprove', { programId: PROGRAMS.squadsV4, key: 'proposal' }],
    ['approvetransaction', { programId: PROGRAMS.squadsV3, key: 'transaction' }],
]);

const EXECUTIONS = new Map([
    ['vaulttransactionexecute', { programId: PROGRAMS.squadsV4, key: 'transaction' }],
    ['executetransaction', { programId: PROGRAMS.squadsV3, key: 'transaction' }],
    ['executeinstruction', { programId: PROGRAMS.squadsV3, key: 'transaction' }],
]);

function proposalCreated(
    tx: ParsedTx,
    ix: ParsedInstruction,
    name: string,
    multisig: WatchedMultisig,
    ctx: DetectorContext,
): Finding | null {
    const isV4 = ix.programId === PROGRAMS.squadsV4 && name === 'vaulttransactioncreate';
    const isV3 = ix.programId === PROGRAMS.squadsV3 && name === 'addinstruction';
    if (!isV4 && !isV3) return null;

    const transaction = account(ix, 'transaction')?.pubkey;
    const proposer = signers(ix)[0] ?? tx.feePayer ?? 'unknown';
    const calls = proposedInstructions(ix, name);
    const described = calls?.map((call) => describeCall(call, ctx)) ?? [
        { text: 'contents could not be decoded', severity: 'medium' as const },
    ];
    const earlier = isV3 && transaction ? ctx.state.proposal(transaction) : undefined;
    const steps = [...(earlier?.steps ?? []), ...described.map((d) => d.text)];
    const summary = collapse(steps).join('; ');
    const severity = maxSeverity('low', earlier?.severity ?? 'low', ...described.map((d) => d.severity));

    const keys = [transaction, isV4 ? sameTransactionProposal(tx, multisig.address) : undefined].filter((k): k is string => Boolean(k));
    ctx.state.rememberProposal(keys, {
        multisig: multisig.address,
        summary,
        steps,
        severity,
        proposer,
        signature: tx.signature,
        slot: tx.slot,
    });

    // upgrade-proposal already alerts on loader changes to watched programs.
    if (calls && calls.length > 0 && calls.every((call) => isWatchedLoaderChange(ix, call, ctx))) return null;

    const firstTime = ctx.state.recordSigners(`proposer:${multisig.address}`, [proposer]).length > 0;
    const details: Record<string, string> = { Proposer: proposer, 'Would do': summary };
    if (transaction) details['Proposal transaction'] = transaction;
    if (firstTime) details['First proposal by this member'] = 'Yes';
    return findingFor(ID, tx, ix, {
        severity: firstTime ? maxSeverity(severity, 'high') : severity,
        title: firstTime ? 'Proposal from a first-time proposer' : 'Multisig proposal created',
        description: `A proposal on ${multisig.label} would ${summary}. ${executionText(multisig)}`,
        subject: multisig.address,
        subjectLabel: multisig.label,
        details,
    });
}

function nonceApproval(tx: ParsedTx, ix: ParsedInstruction, multisig: WatchedMultisig, keyRole: string, ctx: DetectorContext): Finding {
    const member = signers(ix)[0] ?? 'unknown';
    const proposal = proposalFor(ix, keyRole, ctx);
    return findingFor(ID, tx, ix, {
        severity: 'critical',
        title: 'Multisig approval signed with a durable nonce',
        description: `${member} approved a proposal on ${multisig.label} in a durable-nonce transaction, so the signature may have been collected long before it landed. Drift's April 2026 exploit reportedly began with Security Council approvals pre-signed this way.${proposal ? ` The proposal would ${proposal.summary}.` : ''}`,
        subject: multisig.address,
        subjectLabel: multisig.label,
        details: { Member: member, ...(proposal ? { 'Would do': proposal.summary, 'Proposed in': proposal.signature } : {}) },
        stages: ['control'],
    });
}

function executed(tx: ParsedTx, ix: ParsedInstruction, multisig: WatchedMultisig, keyRole: string, ctx: DetectorContext): Finding {
    const proposal = proposalFor(ix, keyRole, ctx);
    const elapsedSeconds = proposal ? ((tx.slot - proposal.slot) * ctx.slotMs) / 1000 : null;
    const elapsed = elapsedSeconds === null ? null : humanDuration(Math.max(elapsedSeconds, 60));
    const rushed = elapsedSeconds !== null && elapsedSeconds < FAST_EXECUTION_SECONDS;
    const nonce = usesDurableNonce(tx);
    let severity = maxSeverity('medium', proposal?.severity ?? 'medium');
    if (rushed) severity = escalate(severity);
    if (nonce) severity = 'critical';

    const details: Record<string, string> = proposal
        ? { Executed: proposal.summary, 'Proposed in': proposal.signature, Proposer: proposal.proposer }
        : {};
    if (elapsed) details['Time since proposal'] = elapsed;
    return findingFor(ID, tx, ix, {
        severity,
        title: nonce
            ? 'Multisig execution signed with a durable nonce'
            : rushed
              ? 'Proposal executed soon after it was created'
              : 'Multisig proposal executed',
        description: proposal
            ? `${multisig.label} executed a proposal to ${proposal.summary}${rushed ? `, ${elapsed} after it was proposed` : ''}.`
            : `${multisig.label} executed a proposal created before the scanned history.`,
        subject: multisig.address,
        subjectLabel: multisig.label,
        details,
        ...(nonce || (rushed && severityRank(severity) >= severityRank('high')) ? { stages: ['control' as const] } : {}),
    });
}

function proposalFor(ix: ParsedInstruction, keyRole: string, ctx: DetectorContext) {
    const keys = [account(ix, keyRole)?.pubkey, account(ix, 'proposal')?.pubkey, account(ix, 'transaction')?.pubkey];
    for (const key of keys) {
        const found = key ? ctx.state.proposal(key) : undefined;
        if (found) return found;
    }
    return undefined;
}

/** System, SPL Token and Stake instruction tags; SPL Token uses a single byte, the others bincode u32. */
const SYSTEM_TRANSFER = 2;
const SYSTEM_ASSIGN = 1;
const TOKEN_CALLS = new Map<number, DescribedCall>([
    [3, { text: 'transfer tokens', severity: 'medium' }],
    [4, { text: 'approve a token delegate', severity: 'high' }],
    [6, { text: 'change a token authority', severity: 'high' }],
    [7, { text: 'mint tokens', severity: 'high' }],
    [9, { text: 'close a token account', severity: 'medium' }],
    [12, { text: 'transfer tokens', severity: 'medium' }],
    [13, { text: 'approve a token delegate', severity: 'high' }],
    [14, { text: 'mint tokens', severity: 'high' }],
]);
const STAKE_CALLS = new Map<number, DescribedCall>([
    [1, { text: 'change a stake authority', severity: 'high' }],
    [4, { text: 'withdraw stake', severity: 'medium' }],
    [6, { text: 'change a stake lockup', severity: 'high' }],
    [8, { text: 'change a stake authority', severity: 'high' }],
    [10, { text: 'change a stake authority', severity: 'high' }],
    [11, { text: 'change a stake authority', severity: 'high' }],
    [12, { text: 'change a stake lockup', severity: 'high' }],
]);

function describeCall(call: ProposedInstruction, ctx: DetectorContext): DescribedCall {
    const data = call.data;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const u32 = data.length >= 4 ? view.getUint32(0, true) : -1;
    const to = (index: number) => call.accounts[index] ?? 'an address from a lookup table';

    if (call.programId === PROGRAMS.system) {
        if (u32 === SYSTEM_TRANSFER && data.length >= 12)
            return { text: `transfer ${formatAmount(view.getBigUint64(4, true), 9)} SOL to ${to(1)}`, severity: 'medium' };
        if (u32 === SYSTEM_ASSIGN) return { text: `reassign ${to(0)} to another program`, severity: 'high' };
        return { text: 'call the System program', severity: 'low' };
    }
    if (call.programId === PROGRAMS.splToken || call.programId === PROGRAMS.token2022) {
        const tag = data[0] ?? -1;
        if ((tag === 3 || tag === 12) && data.length >= 9) {
            const destination = tag === 12 ? to(2) : to(1);
            return {
                text: `transfer ${view.getBigUint64(1, true).toLocaleString('en-US')} raw token units to ${destination}`,
                severity: 'medium',
            };
        }
        return TOKEN_CALLS.get(tag) ?? { text: 'call the token program', severity: 'medium' };
    }
    if (call.programId === PROGRAMS.stake) return STAKE_CALLS.get(u32) ?? { text: 'call the Stake program', severity: 'low' };
    if (call.programId === PROGRAMS.bpfLoaderUpgradeable)
        return { text: `change program ${to(1)} through the upgradeable loader`, severity: 'high' };
    if (SQUADS_PROGRAMS.includes(call.programId)) return { text: 'change Squads multisig settings', severity: 'high' };

    const program = ctx.targets.programs.get(call.programId);
    if (program) {
        const instruction = program.instructionsByDiscriminator.get(Buffer.from(data.subarray(0, 8)).toString('hex'));
        if (!instruction) return { text: `call an unrecognized instruction on ${program.label}`, severity: 'medium' };
        const admin = program.privilegedInstructions.has(normalizeName(instruction));
        return { text: `call ${instruction} on ${program.label}${admin ? ' (admin-only)' : ''}`, severity: admin ? 'high' : 'medium' };
    }
    return { text: `call program ${short(call.programId)}`, severity: 'medium' };
}

/** Merges every repeat of a step, consecutive or not, into one entry with a count. */
function collapse(steps: string[]): string[] {
    const counts = new Map<string, number>();
    for (const step of steps) counts.set(step, (counts.get(step) ?? 0) + 1);
    return [...counts].map(([step, count]) => (count > 1 ? `${step} ×${count}` : step));
}
