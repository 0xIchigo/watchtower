import { createHash } from 'node:crypto';
import { getAddressDecoder } from '@solana/kit';

/** Matched against snake_case instruction names; bare `set_`/`update_` are excluded because end users call them too. */
const PRIVILEGED_NAME = new RegExp(
    [
        'admin',
        'governance',
        'guardian',
        'emergency',
        '(^|_)(un)?pause',
        'halt',
        '(^|_)freeze',
        '(white|allow|block|black)list',
        'upgrade',
        'migrate',
        'set_(authority|owner)',
        'transfer_(ownership|authority|admin)',
        '(update|set|init|initialize)_(global|lending_market|market|reserve|pool|protocol|program|fee|oracle|owner|authority|config)',
        'withdraw_(protocol|treasury|admin)',
        'collect_(protocol_)?fees?',
        'socialize',
        'delever',
        'close_(pool|market|vault|reserve)',
    ].join('|'),
);

/** Matched against lowercase signer names with separators removed; a bare `owner` or `authority` is usually the end user. */
const PRIVILEGED_SIGNER =
    /(admin|governance|guardian|operator|manager|(market|global|protocol|pool|program|config|upgrade|pause|fee)(owner|authority))/;

interface IdlSeed {
    kind: string;
    value?: number[];
}

interface IdlAccountItem {
    name?: string;
    signer?: boolean;
    isSigner?: boolean;
    accounts?: IdlAccountItem[];
    /** Anchor 0.30+: how the account's address is derived. */
    pda?: { seeds?: IdlSeed[]; program?: IdlSeed };
}

type IdlType = string | { array?: [IdlType, number]; defined?: string | { name: string }; option?: IdlType; vec?: IdlType };

interface IdlField {
    name: string;
    type: IdlType;
}

interface IdlTypeDef {
    name: string;
    type?: { kind: string; fields?: IdlField[]; variants?: { fields?: unknown[] }[] };
    discriminator?: number[];
}

interface IdlInstruction {
    name?: string;
    accounts?: IdlAccountItem[];
    /** Present in Anchor 0.30+ IDLs; otherwise derived from the name. */
    discriminator?: number[];
}

export interface IdlSummary {
    instructions: string[];
    /** Admin-only by name or by an admin-like signer. */
    privileged: string[];
    /** Instruction name by hex discriminator. */
    discriminators: Record<string, string>;
    /** Account types that store an admin key, with the fields whose offsets are certain. */
    configLayouts: ConfigLayout[];
}

export interface ConfigField {
    name: string;
    offset: number;
    type: string;
    admin: boolean;
}

export interface ConfigPda {
    /** Hex seeds, all constant. */
    seeds: string[];
    /** Deriving program when it is not the program itself. */
    program: string | null;
}

export interface ConfigLayout {
    account: string;
    /** Hex account discriminator. */
    discriminator: string;
    fields: ConfigField[];
    /** Bytes from the start of the account that cover every field. */
    length: number;
    /** Constant-seed PDAs that instructions pass as this account type. */
    pdas: ConfigPda[];
    /** Some instruction derives this type from a per-entity seed, so its accounts are not protocol settings. */
    perEntity: boolean;
    /** Other account types with a pubkey field naming this type (`namesType`), such as a pool's `whirlpools_config`. */
    referencedBy: { account: string; discriminator: string; offset: number }[];
}

export function summarizeIdl(idl: unknown): IdlSummary {
    const {
        instructions = [],
        accounts = [],
        types = [],
    } = (idl ?? {}) as { instructions?: IdlInstruction[]; accounts?: IdlTypeDef[]; types?: IdlTypeDef[] };
    const names: string[] = [];
    const privileged: string[] = [];
    const discriminators: Record<string, string> = {};
    for (const ix of instructions) {
        if (!ix.name) continue;
        names.push(ix.name);
        discriminators[discriminatorOf(ix)] = ix.name;
        if (PRIVILEGED_NAME.test(snakeCase(ix.name)) || flattenAccounts(ix.accounts ?? []).some(isPrivilegedSigner)) {
            privileged.push(ix.name);
        }
    }
    return { instructions: names, privileged, discriminators, configLayouts: configLayouts(accounts, types, instructions) };
}

/**
 * How instructions derive accounts named after `accountType`: the constant-seed PDAs, and whether any derivation uses
 * a non-constant seed (a mint, a user), which makes the type one account per entity rather than a protocol setting.
 */
function derivations(accountType: string, instructions: IdlInstruction[]): { pdas: ConfigPda[]; perEntity: boolean } {
    const wanted = snakeCase(accountType);
    const pdas = new Map<string, ConfigPda>();
    let perEntity = false;
    for (const item of instructions.flatMap((ix) => flattenAccounts(ix.accounts ?? []))) {
        const { seeds, program } = item.pda ?? {};
        if (item.name === undefined || snakeCase(item.name) !== wanted || !seeds?.length) continue;
        if (!seeds.every((s) => s.kind === 'const' && s.value)) {
            perEntity = true;
            continue;
        }
        if (program && !(program.kind === 'const' && program.value)) continue;
        const pda = {
            seeds: seeds.map((s) => Buffer.from(s.value!).toString('hex')),
            program: program ? getAddressDecoder().decode(Uint8Array.from(program.value!)) : null,
        };
        pdas.set(JSON.stringify(pda), pda);
    }
    return { pdas: [...pdas.values()], perEntity };
}

export const PRIMITIVE_SIZE = new Map<string, number>([
    ['bool', 1],
    ['u8', 1],
    ['i8', 1],
    ['u16', 2],
    ['i16', 2],
    ['u32', 4],
    ['i32', 4],
    ['f32', 4],
    ['u64', 8],
    ['i64', 8],
    ['f64', 8],
    ['u128', 16],
    ['i128', 16],
    ['publicKey', 32],
    ['pubkey', 32],
]);

/** Packed (Borsh) and C-aligned (zero-copy) sizes of a type. */
interface Layout {
    packed: number;
    aligned: number;
    align: number;
}

/**
 * Account types with an admin-like pubkey field, with their leading primitive fields. Fields are read only while the Borsh
 * and C-aligned offsets agree, since the IDL does not say which layout applies; nested structs and arrays are skipped.
 */
function configLayouts(accounts: IdlTypeDef[], types: IdlTypeDef[], instructions: IdlInstruction[]): ConfigLayout[] {
    const byName = new Map(types.map((t) => [t.name, t]));
    const leading = new Map(accounts.map((account) => [account, leadingFields(account, byName)]));
    const layouts: ConfigLayout[] = [];
    for (const [account, fields] of leading) {
        const last = fields.at(-1);
        if (!last || !fields.some((f) => f.admin)) continue;
        layouts.push({
            account: account.name,
            discriminator: accountDiscriminator(account),
            fields,
            length: last.offset + PRIMITIVE_SIZE.get(last.type)!,
            ...derivations(account.name, instructions),
            referencedBy: [...leading].flatMap(([other, otherFields]) =>
                otherFields
                    .filter((f) => other !== account && f.type === 'pubkey' && namesType(f.name, account.name))
                    .map((f) => ({ account: other.name, discriminator: accountDiscriminator(other), offset: f.offset })),
            ),
        });
    }
    return layouts;
}

function leadingFields(account: IdlTypeDef, byName: Map<string, IdlTypeDef>): ConfigField[] {
    const fields: ConfigField[] = [];
    let packed = 8;
    let aligned = 8;
    for (const field of (account.type ?? byName.get(account.name)?.type)?.fields ?? []) {
        const layout = layoutOf(field.type, byName, 0);
        if (!layout) break;
        aligned = alignUp(aligned, layout.align);
        if (packed !== aligned) break;
        if (typeof field.type === 'string') {
            const type = field.type === 'publicKey' ? 'pubkey' : field.type;
            fields.push({
                name: field.name,
                offset: packed,
                type,
                admin: type === 'pubkey' && isAdminRole(field.name) && !/pending/i.test(field.name),
            });
        }
        packed += layout.packed;
        aligned += layout.aligned;
    }
    return fields;
}

function layoutOf(type: IdlType, types: Map<string, IdlTypeDef>, depth: number): Layout | null {
    if (typeof type === 'string') {
        const size = PRIMITIVE_SIZE.get(type);
        if (size === undefined) return null;
        const align = size === 32 ? 1 : Math.min(size, 8);
        return { packed: size, aligned: size, align };
    }
    if (type.array) {
        const element = layoutOf(type.array[0], types, depth);
        return element ? { packed: element.packed * type.array[1], aligned: element.aligned * type.array[1], align: element.align } : null;
    }
    if (type.defined && depth < 8) {
        const def = types.get(typeof type.defined === 'string' ? type.defined : type.defined.name)?.type;
        if (def?.kind === 'enum') return def.variants?.every((v) => !v.fields?.length) ? { packed: 1, aligned: 1, align: 1 } : null;
        if (def?.kind !== 'struct' || !def.fields) return null;
        let packed = 0;
        let aligned = 0;
        let align = 1;
        for (const field of def.fields) {
            const layout = layoutOf(field.type, types, depth + 1);
            if (!layout) return null;
            aligned = alignUp(aligned, layout.align) + layout.aligned;
            packed += layout.packed;
            align = Math.max(align, layout.align);
        }
        return { packed, aligned: alignUp(aligned, align), align };
    }
    return null;
}

function alignUp(offset: number, align: number): number {
    return Math.ceil(offset / align) * align;
}

/** Anchor's account discriminator: sha256("account:<Name>")[..8]. */
function accountDiscriminator(account: IdlTypeDef): string {
    if (account.discriminator?.length) return Buffer.from(account.discriminator).toString('hex');
    return createHash('sha256').update(`account:${account.name}`).digest('hex').slice(0, 16);
}

/** Whether an account or field name refers to `accountType`: `whirlpools_config` or just `config` for `WhirlpoolsConfig`. */
export function namesType(name: string, accountType: string): boolean {
    const [n, type] = [snakeCase(name), snakeCase(accountType)];
    return n === type || type.endsWith(`_${n}`);
}

export function isAdminRole(name: string): boolean {
    return PRIVILEGED_SIGNER.test(name.toLowerCase().replace(/[_-]/g, ''));
}

/** Anchor's instruction discriminator: sha256("global:<snake_case name>")[..8]. */
function discriminatorOf(ix: IdlInstruction): string {
    if (ix.discriminator?.length) return Buffer.from(ix.discriminator).toString('hex');
    return createHash('sha256')
        .update(`global:${snakeCase(ix.name!)}`)
        .digest('hex')
        .slice(0, 16);
}

function isPrivilegedSigner(account: IdlAccountItem): boolean {
    return Boolean((account.signer ?? account.isSigner) && account.name && isAdminRole(account.name));
}

function snakeCase(name: string): string {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

function flattenAccounts(items: IdlAccountItem[]): IdlAccountItem[] {
    return items.flatMap((item) => (item.accounts ? flattenAccounts(item.accounts) : [item]));
}
