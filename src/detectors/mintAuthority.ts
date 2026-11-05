import type { Severity } from '../config.js';
import { PROGRAMS } from '../constants.js';
import { formatAmount, toBigInt } from '../format.js';
import { account, arg, nameOf, normalizeName, pubkeyArg, signers, type ParsedInstruction, type ParsedTx } from '../model.js';
import { findingFor, type Detector, type DetectorContext, type Finding, type WatchedMint } from './types.js';

const ID = 'mint-authority';
const LARGE_MINT_SHARE_OF_SUPPLY = 0.01;

/** Keyed by normalized spl-token-2022 `AuthorityType` variant. */
const AUTHORITY_SEVERITY = new Map<string, Severity>([
    ['minttokens', 'critical'],
    ['freezeaccount', 'high'],
    ['permanentdelegate', 'critical'],
    ['transferhookprogramid', 'critical'],
    ['transferfeeconfig', 'high'],
    ['withheldwithdraw', 'medium'],
    ['closemint', 'high'],
    ['interestrate', 'medium'],
    ['confidentialtransfermint', 'high'],
    ['confidentialtransferfeeconfig', 'medium'],
    ['metadatapointer', 'medium'],
    ['grouppointer', 'low'],
    ['groupmemberpointer', 'low'],
    ['scaleduiamount', 'high'],
    ['pause', 'high'],
    ['permissionedburn', 'high'],
]);

/** Keyed by parser-v2 instruction name. */
export const MINT_EXTENSION_UPDATES = new Map<string, { severity: Severity; title: string }>([
    ['transfer_hook_extension.update', { severity: 'critical', title: 'Transfer hook program changed' }],
    ['pausable_extension.pause', { severity: 'critical', title: 'Token paused' }],
    ['pausable_extension.resume', { severity: 'medium', title: 'Token resumed' }],
    ['transfer_fee_extension.set_transfer_fee', { severity: 'high', title: 'Transfer fee changed' }],
    ['default_account_state_extension.update', { severity: 'high', title: 'Default account state changed' }],
    ['scaled_ui_amount_extension.update_multiplier', { severity: 'high', title: 'UI amount multiplier changed' }],
    ['interest_bearing_mint_extension.update_rate', { severity: 'medium', title: 'Interest rate changed' }],
    ['confidential_transfer_extension.update_mint', { severity: 'medium', title: 'Confidential transfer config changed' }],
    ['transfer_fee_extension.withdraw_withheld_tokens_from_mint', { severity: 'low', title: 'Withheld fees withdrawn' }],
]);

const EXTENSION_UPDATES_BY_NORMALIZED_NAME = new Map([...MINT_EXTENSION_UPDATES].map(([name, rule]) => [normalizeName(name), rule]));

type Classification = { severity: Severity; title: string; description: string; details?: Record<string, string> };

export const mintAuthority: Detector = {
    id: ID,
    description: 'Mint/freeze authority changes, large mints and Token-2022 extension updates on watched mints',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            if (ix.programId !== PROGRAMS.splToken && ix.programId !== PROGRAMS.token2022) continue;
            const name = nameOf(ix);
            const mint = name ? watchedMintOf(ix, ctx) : undefined;
            if (!name || !mint) continue;
            const result = classify(name, ix, mint);
            if (!result) continue;
            const signer = signers(ix)[0];
            findings.push(
                findingFor(ID, tx, ix, {
                    ...result,
                    subject: mint.address,
                    subjectLabel: mint.label,
                    details: {
                        Instruction: ix.instructionName ?? name,
                        ...(signer ? { Signer: signer } : {}),
                        ...result.details,
                    },
                }),
            );
        }
        return findings;
    },
};

function classify(name: string, ix: ParsedInstruction, mint: WatchedMint): Classification | null {
    if (name === 'setauthority') {
        if (account(ix, 'mint_or_account')?.pubkey !== mint.address) return null;
        const authorityType = String(arg(ix, 'authorityType') ?? 'unknown');
        const newAuthority = pubkeyArg(ix, 'newAuthority');
        if (!newAuthority) {
            return {
                severity: 'low',
                title: `${authorityType} authority revoked`,
                description: `The ${authorityType} authority of ${mint.label} was permanently removed.`,
            };
        }
        return {
            severity: AUTHORITY_SEVERITY.get(normalizeName(authorityType)) ?? 'medium',
            title: `${authorityType} authority changed`,
            description: `The ${authorityType} authority of ${mint.label} moved to ${newAuthority}.`,
            details: { 'New authority': newAuthority },
        };
    }

    if (name === 'mintto' || name === 'minttochecked') {
        const amount = toBigInt(arg(ix, 'amount'));
        if (amount === null) return null;
        const share = mint.supply ? Number((amount * 1_000_000n) / mint.supply) / 1_000_000 : null;
        const large = share !== null && share >= LARGE_MINT_SHARE_OF_SUPPLY;
        const shareText = share === null ? '' : ` (${(share * 100).toFixed(2)}% of supply at discovery)`;
        return {
            severity: large ? 'high' : 'info',
            title: large ? 'Large mint' : 'Tokens minted',
            description: `${formatAmount(amount, mint.decimals)} ${mint.label} minted${shareText}.`,
            details: { Amount: amount.toString(), Destination: account(ix, 'destination_account')?.pubkey ?? 'unknown' },
        };
    }

    const extensionUpdate = ix.programId === PROGRAMS.token2022 ? EXTENSION_UPDATES_BY_NORMALIZED_NAME.get(name) : undefined;
    if (extensionUpdate) {
        return {
            ...extensionUpdate,
            description: `${ix.instructionName ?? name} ran on ${mint.label}.`,
            details: ix.args && Object.keys(ix.args).length > 0 ? { Args: JSON.stringify(ix.args).slice(0, 400) } : {},
        };
    }

    if (name === 'freezeaccount') {
        return {
            severity: 'low',
            title: 'Token account frozen',
            description: `A ${mint.label} token account was frozen by the freeze authority.`,
            details: { 'Frozen account': account(ix, 'account')?.pubkey ?? 'unknown' },
        };
    }
    return null;
}

function watchedMintOf(ix: ParsedInstruction, ctx: DetectorContext): WatchedMint | undefined {
    const keys = ix.accounts?.map((a) => a.pubkey) ?? ix.rawAccounts ?? [];
    for (const key of keys) {
        const mint = ctx.targets.mints.get(key);
        if (mint) return mint;
    }
    return undefined;
}
