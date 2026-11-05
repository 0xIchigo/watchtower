import type { Severity } from '../config.js';
import { isAdminRole } from '../discover/idl.js';
import { nameOf, signers, type ParsedInstruction, type ParsedTx } from '../model.js';
import { maxSeverity } from './severity.js';
import { findingFor, type AttackStage, type Detector, type DetectorContext, type Finding, type WatchedProgram } from './types.js';

const ID = 'privileged-instruction';

interface CallClass {
    pattern: RegExp;
    severity: Severity;
    stage: AttackStage;
    /** Adds a token, which `vet.ts` checks via the `Listed mint` detail. */
    listing?: true;
    title(instruction: string): string;
    describe(instruction: string, program: string): string;
}

/** Matched against the snake_case instruction name; first match wins. */
const CALL_CLASSES: CallClass[] = [
    {
        pattern: /(admin|authority|owner|guardian|governance|signer)/,
        severity: 'high',
        stage: 'control',
        title: (ix) => `Admin control changed: ${ix}`,
        describe: (ix, p) => `${ix} on ${p} changes who controls the protocol.`,
    },
    {
        pattern: /^(init|initialize|add|create|list|register)_.*(market|reserve|pool|collateral|asset|bank|vault|spot|perp|token)/,
        severity: 'high',
        stage: 'risk',
        listing: true,
        title: (ix) => `New market or asset added: ${ix}`,
        describe: (ix, p) => `${ix} on ${p} adds a market or asset users can deposit, borrow or trade against.`,
    },
    {
        pattern: /oracle/,
        severity: 'high',
        stage: 'risk',
        title: (ix) => `Oracle changed: ${ix}`,
        describe: (ix, p) => `${ix} on ${p} changes where prices come from.`,
    },
    {
        pattern:
            /^(update|set|change|configure|modify)_.*(limit|weight|ltv|ratio|cap|max|threshold|liquidation|borrow|deposit|withdraw|margin|leverage|param)/,
        severity: 'medium',
        stage: 'risk',
        title: (ix) => `Risk setting changed: ${ix}`,
        describe: (ix, p) => `${ix} on ${p} changes limits or collateral settings.`,
    },
];

export const privilegedInstruction: Detector = {
    id: ID,
    description: 'Calls and failed attempts on admin-only instructions of watched programs, and new signers on them',
    includeFailed: true,
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            const program = ctx.targets.programs.get(ix.programId);
            const name = nameOf(ix);
            if (!program || !name || !program.privilegedInstructions.has(name)) continue;
            findings.push(tx.succeeded ? succeeded(tx, ix, program, name, ctx) : failed(tx, ix, program, name, ctx));
        }
        return findings;
    },
};

function succeeded(tx: ParsedTx, ix: ParsedInstruction, program: WatchedProgram, name: string, ctx: DetectorContext): Finding {
    const ixSigners = signers(ix);
    const unseen = ctx.state.recordSigners(`${program.id}:${name}`, ixSigners);
    const newSigner = unseen.length > 0;
    const adminSigners = ix.accounts?.filter((a) => a.isSigner && isAdminRole(a.name)) ?? [];
    for (const signer of adminSigners) ctx.state.recordAdminKey(program.id, signer.pubkey, signer.name);
    const instruction = ix.instructionName ?? name;
    const kind = CALL_CLASSES.find((c) => c.pattern.test(snakeCase(instruction)));
    const severity = maxSeverity(kind?.severity ?? 'medium', newSigner ? 'high' : 'low');
    const listedMint = kind?.listing ? listedMintOf(ix) : undefined;
    const stages = [...new Set([...(newSigner ? ['control' as const] : []), ...(kind ? [kind.stage] : [])])];
    return findingFor(ID, tx, ix, {
        severity,
        title: newSigner ? `New signer on ${instruction}` : (kind?.title(instruction) ?? `${instruction} called`),
        description: [
            newSigner ? `${instruction} on ${program.label} was signed by ${unseen.join(', ')}, which has not signed it before.` : '',
            kind
                ? kind.describe(instruction, program.label)
                : newSigner
                  ? ''
                  : `Privileged instruction ${instruction} ran on ${program.label}.`,
        ]
            .filter(Boolean)
            .join(' '),
        subject: program.id,
        subjectLabel: program.label,
        details: {
            ...details(tx, ix, ixSigners),
            ...(listedMint ? { 'Listed mint': listedMint } : {}),
            ...(adminSigners[0] ? { 'Admin signer': adminSigners[0].pubkey } : {}),
        },
        ...(stages.length > 0 ? { stages } : {}),
    });
}

function listedMintOf(ix: ParsedInstruction): string | undefined {
    return ix.accounts?.find((a) => /mint/i.test(a.name) && !/authority|program/i.test(a.name))?.pubkey;
}

function snakeCase(name: string): string {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

function failed(tx: ParsedTx, ix: ParsedInstruction, program: WatchedProgram, name: string, ctx: DetectorContext): Finding {
    const ixSigners = signers(ix);
    const known = ctx.state.knownSigners(`${program.id}:${name}`);
    const unknown = ixSigners.filter((s) => !known.includes(s));
    const instruction = ix.instructionName ?? name;
    const outsider = unknown.length > 0 || ixSigners.length === 0;
    return findingFor(ID, tx, ix, {
        severity: outsider ? 'high' : 'low',
        title: outsider ? `Unauthorized attempt on ${instruction}` : `${instruction} failed`,
        description: outsider
            ? `${unknown.join(', ') || 'An unknown signer'} tried to call ${instruction} on ${program.label} and the transaction failed.`
            : `A known signer's call to ${instruction} on ${program.label} failed.`,
        subject: program.id,
        subjectLabel: program.label,
        details: { ...details(tx, ix, ixSigners), Error: tx.errorText ?? 'unknown' },
    });
}

const MAX_TARGET_ACCOUNTS = 4;

function details(tx: ParsedTx, ix: ParsedInstruction, ixSigners: string[]): Record<string, string> {
    const targets = (ix.accounts ?? [])
        .filter((a) => a.isWritable && !a.isSigner)
        .slice(0, MAX_TARGET_ACCOUNTS)
        .map((a) => `${a.name} ${a.pubkey}`);
    return {
        Signers: ixSigners.join(', ') || tx.feePayer || 'none decoded',
        ...(targets.length > 0 ? { 'Accounts changed': targets.join(', ') } : {}),
        ...(ix.args && Object.keys(ix.args).length > 0 ? { Args: truncate(JSON.stringify(ix.args)) } : {}),
    };
}

function truncate(text: string, max = 400): string {
    return text.length > max ? `${text.slice(0, max)}…` : text;
}
