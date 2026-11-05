import { getAddressDecoder } from '@solana/kit';
import type {
    DecodedAccount,
    ParsedInstruction as SdkInstruction,
    ParsedNativeTransfer,
    ParsedSummary,
    ParsedTokenTransfer,
    ParsedTransactionResult,
} from 'helius-sdk/parsedEvents/types';
import type { ParsedStreamInstruction, ParsedTransactionValue } from 'helius-sdk/websockets/parsedStreams';

export interface ParsedTx {
    signature: string;
    slot: number;
    /** Unix seconds; `null` from Parsed Streams. */
    blockTime: number | null;
    feePayer: string | null;
    succeeded: boolean;
    errorText: string | null;
    summary: ParsedSummary | null;
    /** Top-level instructions followed by their inner instructions, in execution order. */
    instructions: ParsedInstruction[];
    /** Amounts can arrive as strings beyond the JS safe-integer range; read them with `toBigInt`. */
    nativeTransfers: ParsedNativeTransfer[];
    tokenTransfers: ParsedTokenTransfer[];
    source: 'backfill' | 'stream';
}

export type { ParsedNativeTransfer as NativeTransfer, ParsedTokenTransfer as TokenTransfer } from 'helius-sdk/parsedEvents/types';

export interface ParsedInstruction {
    instructionIndex: number;
    /** `null` for a top-level instruction. */
    innerInstructionIndex: number | null;
    stackHeight: number | null;
    programId: string;
    programName: string | null;
    instructionName: string | null;
    /** `null` when the parser has no decoder for the instruction. */
    args: Record<string, unknown> | null;
    accounts: DecodedAccount[] | null;
    rawAccounts: string[] | null;
    summary: ParsedSummary | null;
}

type WireInstruction = SdkInstruction | ParsedStreamInstruction;

export function fromParsedEvents(result: ParsedTransactionResult): ParsedTx | null {
    if (result.parserStatus !== 'OK') return null;
    const parsed = result.parsed;
    return {
        signature: result.signature,
        slot: parsed.slot,
        blockTime: parsed.blockTime,
        feePayer: parsed.feePayer,
        succeeded: parsed.transactionStatus.toUpperCase() === 'OK',
        errorText: parsed.decodedError?.name ?? parsed.decodedError?.msg ?? errorText(parsed.error),
        summary: parsed.summary ?? null,
        instructions: parsed.instructions.map(toInstruction),
        nativeTransfers: parsed.nativeTransfers ?? [],
        tokenTransfers: parsed.tokenTransfers ?? [],
        source: 'backfill',
    };
}

export function fromStream(value: ParsedTransactionValue): ParsedTx {
    const tx = value.transaction;
    return {
        signature: tx.signature,
        slot: tx.slot,
        blockTime: tx.blockTime,
        feePayer: tx.feePayer,
        succeeded: tx.status === 'ok',
        errorText: errorText(tx.error),
        summary: tx.summary ?? null,
        instructions: value.instructions.map(toInstruction),
        nativeTransfers: tx.nativeTransfers ?? [],
        tokenTransfers: tx.tokenTransfers ?? [],
        source: 'stream',
    };
}

function errorText(error: unknown): string | null {
    if (error === null || error === undefined) return null;
    return typeof error === 'string' ? error : JSON.stringify(error);
}

function toInstruction(ix: WireInstruction): ParsedInstruction {
    return {
        instructionIndex: ix.instructionIndex ?? 0,
        innerInstructionIndex: ix.innerInstructionIndex ?? null,
        stackHeight: ix.stackHeight ?? null,
        programId: ix.programId,
        programName: ix.programName ?? null,
        instructionName: ix.instructionName ?? null,
        args: ix.decoded?.args ?? null,
        accounts: ix.decoded?.accounts ?? null,
        rawAccounts: ix.rawAccounts ?? null,
        summary: ix.summary ?? null,
    };
}

/** Case- and separator-insensitive form, matching how Parsed Streams compares instruction names. */
export function normalizeName(name: string): string {
    return name.toLowerCase().replace(/[_\-\s]/g, '');
}

export function nameOf(ix: ParsedInstruction): string | null {
    return ix.instructionName === null ? null : normalizeName(ix.instructionName);
}

export function account(ix: ParsedInstruction, role: string): DecodedAccount | undefined {
    const wanted = normalizeName(role);
    return ix.accounts?.find((a) => normalizeName(a.name) === wanted);
}

export function signers(ix: ParsedInstruction): string[] {
    return ix.accounts?.filter((a) => a.isSigner).map((a) => a.pubkey) ?? [];
}

export function parentOf(tx: ParsedTx, ix: ParsedInstruction): ParsedInstruction | undefined {
    if (ix.innerInstructionIndex === null) return undefined;
    return tx.instructions.find(
        (candidate) => candidate.instructionIndex === ix.instructionIndex && candidate.innerInstructionIndex === null,
    );
}

/** First present key, as given or in snake_case. */
export function arg(ix: ParsedInstruction, ...keys: string[]): unknown {
    return ix.args ? field(ix.args, ...keys) : undefined;
}

/** `arg` for a nested decoded object. */
export function field(value: unknown, ...keys: string[]): unknown {
    if (!value || typeof value !== 'object') return undefined;
    const record = value as Record<string, unknown>;
    for (const key of keys) {
        for (const spelling of [key, snakeCase(key)]) {
            if (Object.hasOwn(record, spelling)) return record[spelling];
        }
    }
    return undefined;
}

function snakeCase(key: string): string {
    return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

/**
 * A public-key arg as base58, unwrapping `COption`. parser-v2's native decoders can split a bare `Pubkey` tuple payload
 * into bytes: the named field holds byte 0 and `field_2`..`field_32` hold the rest.
 */
export function pubkeyArg(ix: ParsedInstruction, key: string): string | undefined {
    let value = arg(ix, key);
    if (value && typeof value === 'object' && !Array.isArray(value)) value = field(value, 'Some', 'some');
    if (typeof value === 'string' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value) && !/^\d+$/.test(value)) return value;
    const bytes = Array.isArray(value) ? value : [value, ...Array.from({ length: 31 }, (_, i) => ix.args?.[`field_${i + 2}`])];
    const numbers = bytes.map(Number);
    if (numbers.length !== 32 || numbers.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return undefined;
    return getAddressDecoder().decode(Uint8Array.from(numbers));
}
