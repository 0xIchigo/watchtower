import type { Severity } from '../config.js';
import { PROGRAMS, SQUADS_PROGRAMS } from '../constants.js';
import { account, nameOf, parentOf, type ParsedInstruction, type ParsedTx } from '../model.js';
import { findingFor, type Detector, type DetectorContext, type Finding, type WatchedProgram } from './types.js';

const ID = 'program-deployment';

interface LoaderRule {
    severity: Severity;
    title: string;
    describe(program: WatchedProgram, ix: ParsedInstruction): string;
}

const EXTEND: LoaderRule = {
    severity: 'low',
    title: 'Program data extended',
    describe: (p) => `The ProgramData account of ${p.label} was resized, usually ahead of an upgrade.`,
};

/** Keyed by normalized parser-v2 `bpf_loader_upgradeable` instruction names. */
const RULES = new Map<string, (ix: ParsedInstruction) => LoaderRule>([
    ['upgrade', () => ({ severity: 'high', title: 'Program upgraded', describe: (p) => `New bytecode was deployed to ${p.label}.` })],
    ['setauthority', authorityRule],
    ['setauthoritychecked', authorityRule],
    [
        'close',
        () => ({
            severity: 'critical',
            title: 'Program closed',
            describe: (p) => `${p.label} was closed and its lamports reclaimed. The program can no longer be invoked.`,
        }),
    ],
    [
        'migrate',
        () => ({
            severity: 'high',
            title: 'Program migrated to loader-v4',
            describe: (p) => `${p.label} was migrated off the upgradeable loader.`,
        }),
    ],
    ['extendprogram', () => EXTEND],
    ['extendprogramchecked', () => EXTEND],
    [
        'deploywithmaxdatalen',
        () => ({ severity: 'info', title: 'Program deployed', describe: (p) => `${p.label} was deployed for the first time.` }),
    ],
]);

export const programDeployment: Detector = {
    id: ID,
    description: 'Upgrades, upgrade-authority changes, closes and resizes of watched programs',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            const classified = classifyLoaderInstruction(ix, ctx);
            if (!classified) continue;
            const { program, rule } = classified;
            findings.push(
                findingFor(ID, tx, ix, {
                    severity: rule.severity,
                    title: rule.title,
                    description: rule.describe(program, ix),
                    subject: program.id,
                    subjectLabel: program.label,
                    details: detailsFor(tx, ix),
                }),
            );
        }
        return findings;
    },
};

export function classifyLoaderInstruction(
    ix: ParsedInstruction,
    ctx: DetectorContext,
): { program: WatchedProgram; rule: LoaderRule; name: string } | null {
    if (ix.programId !== PROGRAMS.bpfLoaderUpgradeable) return null;
    const name = nameOf(ix);
    const program = watchedProgramOf(ix, ctx);
    const ruleFor = name ? RULES.get(name) : undefined;
    return name && program && ruleFor ? { program, rule: ruleFor(ix), name } : null;
}

function authorityRule(ix: ParsedInstruction): LoaderRule {
    const newAuthority = account(ix, 'new_authority')?.pubkey;
    if (!newAuthority) {
        return {
            severity: 'high',
            title: 'Program made immutable',
            describe: (p) => `The upgrade authority of ${p.label} was removed. This cannot be undone.`,
        };
    }
    return {
        severity: 'critical',
        title: 'Upgrade authority changed',
        describe: (p) => `Control over upgrades to ${p.label} moved to ${newAuthority}.`,
    };
}

function watchedProgramOf(ix: ParsedInstruction, ctx: DetectorContext): WatchedProgram | undefined {
    const program = account(ix, 'program_account')?.pubkey;
    const byProgram = program ? ctx.targets.programs.get(program) : undefined;
    if (byProgram) return byProgram;
    for (const role of ['program_data_account', 'target_account']) {
        const key = account(ix, role)?.pubkey;
        const watched = key ? ctx.targets.programsByProgramData.get(key) : undefined;
        if (watched) return watched;
    }
    return undefined;
}

function detailsFor(tx: ParsedTx, ix: ParsedInstruction): Record<string, string> {
    const details: Record<string, string> = {};
    for (const [label, role] of [
        ['Authority', 'authority'],
        ['Current authority', 'current_authority'],
        ['New authority', 'new_authority'],
        ['Buffer', 'buffer_account'],
        ['Spill account', 'spill_account'],
        ['Recipient', 'recipient_account'],
    ] as const) {
        const key = account(ix, role)?.pubkey;
        if (key) details[label] = key;
    }
    const parent = parentOf(tx, ix);
    if (parent && SQUADS_PROGRAMS.includes(parent.programId)) {
        details['Executed via'] = `Squads multisig ${account(parent, 'multisig')?.pubkey ?? '(unknown)'}`;
    } else if (parent) {
        details['Executed via'] = `CPI from ${parent.programName ?? parent.programId}`;
    } else {
        details['Executed via'] = 'Direct signature (no multisig)';
    }
    if (tx.feePayer) details['Fee payer'] = tx.feePayer;
    return details;
}
