import type { Severity } from '../config.js';
import { PROGRAMS } from '../constants.js';
import { decodeV4TransactionMessage, type ProposedInstruction } from '../discover/squads.js';
import { humanDuration } from '../format.js';
import { account, arg, field, nameOf, signers, type ParsedInstruction, type ParsedTx } from '../model.js';
import { classifyLoaderInstruction } from './programDeployment.js';
import { findingFor, type Detector, type DetectorContext, type Finding, type WatchedMultisig } from './types.js';

const ID = 'upgrade-proposal';

/** Upgradeable-loader tags (bincode u32) and their account roles by position. */
const LOADER_LAYOUTS = new Map<number, { name: string; roles: string[] }>([
    [
        3,
        {
            name: 'upgrade',
            roles: [
                'program_data_account',
                'program_account',
                'buffer_account',
                'spill_account',
                'rent_sysvar',
                'clock_sysvar',
                'authority',
            ],
        },
    ],
    [4, { name: 'set_authority', roles: ['target_account', 'current_authority', 'new_authority'] }],
    [5, { name: 'close', roles: ['target_account', 'recipient_account', 'authority', 'program_account'] }],
    [7, { name: 'set_authority_checked', roles: ['target_account', 'current_authority', 'new_authority'] }],
    [8, { name: 'migrate', roles: ['program_data_account', 'program_account', 'authority'] }],
]);

interface ProposalRule {
    title: string;
    severity: Severity;
    describe(program: string, newAuthority: string | undefined): string;
}

const AUTHORITY_CHANGE: ProposalRule = {
    title: 'Upgrade authority change proposed',
    severity: 'critical',
    describe: (p, to) => (to ? `move upgrade authority over ${p} to ${to}` : `make ${p} immutable`),
};

const PROPOSAL_RULES = new Map<string, ProposalRule>([
    ['upgrade', { title: 'Program upgrade proposed', severity: 'high', describe: (p) => `deploy new bytecode to ${p}` }],
    ['setauthority', AUTHORITY_CHANGE],
    ['setauthoritychecked', AUTHORITY_CHANGE],
    ['close', { title: 'Program close proposed', severity: 'critical', describe: (p) => `close ${p} permanently` }],
    ['migrate', { title: 'Loader migration proposed', severity: 'high', describe: (p) => `migrate ${p} to loader-v4` }],
]);

export const upgradeProposal: Detector = {
    id: ID,
    description: 'Program upgrades and authority changes proposed in a Squads multisig, before they execute',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            const multisig = account(ix, 'multisig')?.pubkey;
            const watched = multisig ? ctx.targets.multisigs.get(multisig) : undefined;
            const name = nameOf(ix);
            if (!watched || !name) continue;

            const proposed = proposedInstructions(ix, name);
            if (proposed) {
                findings.push(...proposalFindings(tx, ix, watched, proposed, ctx));
                continue;
            }

            const proposalKey = approvalTarget(ix, name);
            const change = proposalKey ? ctx.state.proposedChange(proposalKey) : undefined;
            if (!change) continue;
            const member = signers(ix)[0] ?? 'unknown';
            findings.push(
                findingFor(ID, tx, ix, {
                    severity: 'medium',
                    title: `${change.title.replace(/ proposed$/, '')} approved by a member`,
                    description: `${member} approved the proposal on ${watched.label}. ${executionText(watched)}`,
                    subject: watched.address,
                    subjectLabel: watched.label,
                    details: { Member: member, 'Proposed in': change.signature },
                }),
            );
        }
        return findings;
    },
};

function proposalFindings(
    tx: ParsedTx,
    ix: ParsedInstruction,
    multisig: WatchedMultisig,
    proposed: ProposedInstruction[],
    ctx: DetectorContext,
): Finding[] {
    const findings: Finding[] = [];
    const transaction = account(ix, 'transaction')?.pubkey;
    const keys = [transaction, sameTransactionProposal(tx, multisig.address)].filter((k): k is string => Boolean(k));
    const proposer = signers(ix)[0] ?? tx.feePayer ?? 'unknown';
    for (const call of proposed) {
        const synthetic = asParsedInstruction(ix, call);
        const classified = synthetic ? classifyLoaderInstruction(synthetic, ctx) : null;
        const proposal = classified ? PROPOSAL_RULES.get(classified.name) : undefined;
        if (!synthetic || !classified || !proposal) continue;

        ctx.state.rememberProposedChange(keys, {
            multisig: multisig.address,
            program: classified.program.id,
            title: proposal.title,
            signature: tx.signature,
            slot: tx.slot,
        });

        const details: Record<string, string> = { Proposer: proposer, Program: classified.program.id };
        const buffer = synthetic.accounts?.find((a) => a.name === 'buffer_account')?.pubkey;
        const newAuthority = synthetic.accounts?.find((a) => a.name === 'new_authority')?.pubkey;
        if (buffer) details.Buffer = buffer;
        if (newAuthority) details['New authority'] = newAuthority;
        if (transaction) details['Proposal transaction'] = transaction;

        findings.push(
            findingFor(ID, tx, ix, {
                severity: proposal.severity,
                title: proposal.title,
                description: `A proposal on ${multisig.label} would ${proposal.describe(classified.program.label, newAuthority)}. ${executionText(multisig)}`,
                subject: multisig.address,
                subjectLabel: multisig.label,
                details,
            }),
        );
    }
    return findings;
}

/** Squads v4 instructions that create a vault transaction: directly, or from a transaction buffer (`decodeTransactionBuffers`). */
export const V4_TRANSACTION_CREATES = new Set(['vaulttransactioncreate', 'vaulttransactioncreatefrombuffer']);

/** v4 `vaultTransactionCreate` carries the whole proposed message; v3 adds instructions one at a time. */
export function proposedInstructions(ix: ParsedInstruction, name: string): ProposedInstruction[] | null {
    if (ix.programId === PROGRAMS.squadsV4 && V4_TRANSACTION_CREATES.has(name)) {
        const message = field(arg(ix, 'args'), 'transactionMessage');
        if (typeof message !== 'string') return null;
        try {
            return decodeV4TransactionMessage(Buffer.from(message, 'base64'));
        } catch (error) {
            console.warn(`Failed to decode a Squads v4 transaction message: ${(error as Error).message}`);
            return null;
        }
    }
    if (ix.programId === PROGRAMS.squadsV3 && name === 'addinstruction') {
        const incoming = arg(ix, 'incomingInstruction');
        const programId = field(incoming, 'programId');
        const keys = field(incoming, 'keys') as { pubkey: string }[] | undefined;
        const data = field(incoming, 'data');
        if (typeof programId !== 'string' || !Array.isArray(keys) || typeof data !== 'string') return null;
        return [{ programId, accounts: keys.map((k) => k.pubkey), data: Buffer.from(data, 'base64') }];
    }
    return null;
}

function asParsedInstruction(parent: ParsedInstruction, call: ProposedInstruction): ParsedInstruction | null {
    if (call.programId !== PROGRAMS.bpfLoaderUpgradeable || call.data.length < 4) return null;
    const layout = LOADER_LAYOUTS.get(new DataView(call.data.buffer, call.data.byteOffset, 4).getUint32(0, true));
    if (!layout) return null;
    return {
        ...parent,
        programId: call.programId,
        programName: 'bpf_loader_upgradeable',
        instructionName: layout.name,
        args: {},
        accounts: layout.roles.flatMap((name, i) => {
            const pubkey = call.accounts[i];
            return pubkey ? [{ name, pubkey, isSigner: false, isWritable: false }] : [];
        }),
        rawAccounts: null,
    };
}

export function isWatchedLoaderChange(parent: ParsedInstruction, call: ProposedInstruction, ctx: DetectorContext): boolean {
    const synthetic = asParsedInstruction(parent, call);
    const classified = synthetic ? classifyLoaderInstruction(synthetic, ctx) : null;
    return Boolean(classified && PROPOSAL_RULES.has(classified.name));
}

/** The v4 proposal account created in the same transaction, which approvals reference. */
export function sameTransactionProposal(tx: ParsedTx, multisig: string): string | undefined {
    const create = tx.instructions.find(
        (ix) => ix.programId === PROGRAMS.squadsV4 && nameOf(ix) === 'proposalcreate' && account(ix, 'multisig')?.pubkey === multisig,
    );
    return create ? account(create, 'proposal')?.pubkey : undefined;
}

function approvalTarget(ix: ParsedInstruction, name: string): string | undefined {
    if (ix.programId === PROGRAMS.squadsV4 && name === 'proposalapprove') return account(ix, 'proposal')?.pubkey;
    if (ix.programId === PROGRAMS.squadsV3 && name === 'approvetransaction') return account(ix, 'transaction')?.pubkey;
    return undefined;
}

export function executionText(multisig: WatchedMultisig): string {
    const approvals = multisig.threshold ? `${multisig.threshold} approvals` : 'the required approvals';
    if (multisig.version === 3) return `Squads v3 has no time lock, so it can execute as soon as it has ${approvals}.`;
    if (multisig.timeLockSeconds) return `It can execute after ${approvals} and a ${humanDuration(multisig.timeLockSeconds)} time lock.`;
    return `It can execute as soon as it has ${approvals}; there is no time lock.`;
}
