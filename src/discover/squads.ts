import { address, getAddressDecoder, getAddressEncoder, getBase58Encoder, getProgramDerivedAddress } from '@solana/kit';
import { PROGRAMS } from '../constants.js';
import type { ParsedTx } from '../model.js';
import type { StateStore } from '../state.js';

/** Anchor discriminators: sha256("account:Multisig")[..8] (v4) and sha256("account:Ms")[..8] (v3). */
const V4_MULTISIG_DISCRIMINATOR = 'e07479ba44a14fec';
const V3_MS_DISCRIMINATOR = '4676096cfed71f78';
const VAULT_INDEXES_CHECKED = 16;

interface SquadsMember {
    key: string;
    canInitiate: boolean;
    canVote: boolean;
    canExecute: boolean;
}

export interface SquadsMultisig {
    version: 3 | 4;
    address: string;
    createKey: string;
    /** `null` for an autonomous multisig (only member votes change the config), and always on v3. */
    configAuthority: string | null;
    threshold: number;
    /** Always 0 on v3. */
    timeLockSeconds: number;
    transactionIndex: bigint;
    members: SquadsMember[];
}

function multisigVersion(owner: string, data: Uint8Array): 3 | 4 | null {
    const discriminator = Buffer.from(data.subarray(0, 8)).toString('hex');
    if (owner === PROGRAMS.squadsV4 && discriminator === V4_MULTISIG_DISCRIMINATOR) return 4;
    if (owner === PROGRAMS.squadsV3 && discriminator === V3_MS_DISCRIMINATOR) return 3;
    return null;
}

export function decodeMultisig(multisigAddress: string, owner: string, data: Uint8Array): SquadsMultisig | null {
    switch (multisigVersion(owner, data)) {
        case 4:
            return decodeV4(multisigAddress, data);
        case 3:
            return decodeV3(multisigAddress, data);
        case null:
            return null;
    }
}

/** Borsh `Multisig` from squads-protocol/v4. */
function decodeV4(multisigAddress: string, data: Uint8Array): SquadsMultisig {
    const r = new Reader(data, 8);
    const createKey = r.address();
    const configAuthority = r.address();
    const threshold = r.u16();
    const timeLockSeconds = r.u32();
    const transactionIndex = r.u64();
    r.skip(8); // stale_transaction_index
    if (r.u8() === 1) r.skip(32); // rent_collector: Option<Pubkey>
    r.skip(1); // bump
    const members = Array.from({ length: r.u32() }, () => {
        const key = r.address();
        const mask = r.u8();
        return { key, canInitiate: (mask & 1) !== 0, canVote: (mask & 2) !== 0, canExecute: (mask & 4) !== 0 };
    });
    return {
        version: 4,
        address: multisigAddress,
        createKey,
        configAuthority: configAuthority === PROGRAMS.system ? null : configAuthority,
        threshold,
        timeLockSeconds,
        transactionIndex,
        members,
    };
}

/** Borsh `Ms` from Squads-Protocol/squads-mpl. v3 members have every permission. */
function decodeV3(multisigAddress: string, data: Uint8Array): SquadsMultisig {
    const r = new Reader(data, 8);
    const threshold = r.u16();
    r.skip(2); // authority_index
    const transactionIndex = BigInt(r.u32());
    r.skip(4 + 1); // ms_change_index, bump
    const createKey = r.address();
    r.skip(1); // allow_external_execute
    const members = Array.from({ length: r.u32() }, () => ({
        key: r.address(),
        canInitiate: true,
        canVote: true,
        canExecute: true,
    }));
    return {
        version: 3,
        address: multisigAddress,
        createKey,
        configAuthority: null,
        threshold,
        timeLockSeconds: 0,
        transactionIndex,
        members,
    };
}

async function vaultAddress(version: 3 | 4, multisig: string, index: number): Promise<string> {
    const multisigBytes = getAddressEncoder().encode(address(multisig));
    if (version === 4) {
        const [pda] = await getProgramDerivedAddress({
            programAddress: address(PROGRAMS.squadsV4),
            seeds: ['multisig', multisigBytes, 'vault', new Uint8Array([index])],
        });
        return pda;
    }
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, true);
    const [pda] = await getProgramDerivedAddress({
        programAddress: address(PROGRAMS.squadsV3),
        seeds: ['squad', multisigBytes, indexBytes, 'authority'],
    });
    return pda;
}

/** The vault (v4) or authority (v3) index of `candidate` among the multisig's first `VAULT_INDEXES_CHECKED` PDAs. */
export async function findVaultIndex(version: 3 | 4, multisig: string, candidate: string): Promise<number | null> {
    for (let index = 0; index < VAULT_INDEXES_CHECKED; index++) {
        if ((await vaultAddress(version, multisig, index)) === candidate) return index;
    }
    return null;
}

export function votingMembers(multisig: SquadsMultisig): number {
    return multisig.members.filter((m) => m.canVote).length;
}

export interface ProposedInstruction {
    programId: string;
    /** `null` where the key comes from an address lookup table. */
    accounts: (string | null)[];
    data: Uint8Array;
}

/** Squads v4 `TransactionMessage` (`vaultTransactionCreate` arg): vectors have a u8 length prefix, instruction data a u16. */
export function decodeV4TransactionMessage(bytes: Uint8Array): ProposedInstruction[] {
    const r = new Reader(bytes, 0);
    r.skip(3); // num_signers, num_writable_signers, num_writable_non_signers
    const accountKeys = Array.from({ length: r.u8() }, () => r.address());
    const keyAt = (index: number) => accountKeys[index] ?? null;
    return Array.from({ length: r.u8() }, () => {
        const programIdIndex = r.u8();
        const accountIndexes = Array.from({ length: r.u8() }, () => r.u8());
        const data = r.bytes(r.u16());
        return { programId: keyAt(programIdIndex) ?? 'unknown', accounts: accountIndexes.map(keyAt), data };
    });
}

/**
 * Anchor discriminators (sha256("global:<name>")[..8]) of the Squads v4 transaction-buffer instructions, which the IDL
 * Parsed Events holds does not include, so they arrive undecoded with `rawData` and `rawAccounts`.
 */
const BUFFER_CREATE = 'f5c9716c253f1d59';
const BUFFER_EXTEND = 'e69d433805eef592';
const CREATE_FROM_BUFFER = 'de36954457f630e7';

/** `vaultTransactionCreateFromBuffer` accounts by position: `VaultTransactionCreate`'s, then the buffer and creator. */
const FROM_BUFFER_ACCOUNTS = ['multisig', 'transaction', 'creator', 'rent_payer', 'system_program', 'transaction_buffer', 'creator'];
const FROM_BUFFER_SIGNERS = new Set(['creator', 'rent_payer']);

/**
 * Decodes the transaction-buffer instructions in `tx` in place. A buffer is written by `transactionBufferCreate`
 * (args: buffer_index u8, vault_index u8, final_buffer_hash [u8; 32], final_buffer_size u16, buffer Vec<u8>) and
 * `transactionBufferExtend` (buffer Vec<u8>), then `vaultTransactionCreateFromBuffer` turns it into a proposal. That
 * instruction is renamed and given decoded accounts and a `transaction_message` arg, so it reads like
 * `vaultTransactionCreate`; the message is left out when the buffer was not seen in full.
 */
export function decodeTransactionBuffers(tx: ParsedTx, state: StateStore): void {
    for (const ix of tx.instructions) {
        if (ix.programId !== PROGRAMS.squadsV4 || ix.instructionName !== null || !ix.rawData || !ix.rawAccounts) continue;
        const data = Uint8Array.from(getBase58Encoder().encode(ix.rawData));
        const discriminator = Buffer.from(data.subarray(0, 8)).toString('hex');
        const id = `${tx.signature}:${ix.instructionIndex}.${ix.innerInstructionIndex ?? ''}`;
        const r = new Reader(data, 8);
        if (discriminator === BUFFER_CREATE && ix.rawAccounts[1]) {
            r.skip(2); // buffer_index, vault_index
            const finalHash = Buffer.from(r.bytes(32)).toString('hex');
            const finalSize = r.u16();
            state.startTransactionBuffer(ix.rawAccounts[1], id, finalHash, finalSize, r.bytes(r.u32()));
        } else if (discriminator === BUFFER_EXTEND && ix.rawAccounts[1]) {
            state.extendTransactionBuffer(ix.rawAccounts[1], id, r.bytes(r.u32()));
        } else if (discriminator === CREATE_FROM_BUFFER && ix.rawAccounts.length >= FROM_BUFFER_ACCOUNTS.length) {
            const vaultIndex = r.u8();
            const ephemeralSigners = r.u8();
            const message = state.transactionBuffer(ix.rawAccounts[5]!);
            ix.instructionName = 'vault_transaction_create_from_buffer';
            ix.accounts = FROM_BUFFER_ACCOUNTS.map((name, i) => ({
                name,
                pubkey: ix.rawAccounts![i]!,
                isSigner: FROM_BUFFER_SIGNERS.has(name),
                isWritable: name !== 'system_program',
            }));
            ix.args = {
                args: {
                    vault_index: vaultIndex,
                    ephemeral_signers: ephemeralSigners,
                    ...(message ? { transaction_message: Buffer.from(message).toString('base64') } : {}),
                },
            };
        }
    }
}

class Reader {
    readonly #data: Uint8Array;
    readonly #view: DataView;
    #offset: number;

    constructor(data: Uint8Array, offset: number) {
        this.#data = data;
        this.#view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        this.#offset = offset;
    }

    skip(bytes: number): void {
        this.#offset += bytes;
    }

    u8(): number {
        return this.#view.getUint8(this.#offset++);
    }

    u16(): number {
        const value = this.#view.getUint16(this.#offset, true);
        this.#offset += 2;
        return value;
    }

    u32(): number {
        const value = this.#view.getUint32(this.#offset, true);
        this.#offset += 4;
        return value;
    }

    u64(): bigint {
        const value = this.#view.getBigUint64(this.#offset, true);
        this.#offset += 8;
        return value;
    }

    address(): string {
        return getAddressDecoder().decode(this.bytes(32));
    }

    bytes(length: number): Uint8Array {
        if (this.#offset + length > this.#data.length) throw new RangeError('read past end of Squads account data');
        const value = this.#data.subarray(this.#offset, this.#offset + length);
        this.#offset += length;
        return value;
    }
}
