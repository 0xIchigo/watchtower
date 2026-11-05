import { createHash } from 'node:crypto';
import type { RpcClient } from '../helius/rpc.js';

const DEFAULT_VERIFY_URL = 'https://verify.osec.io';
/** Upgradeable-loader ProgramData: u32 tag, u64 deploy slot, Option<Pubkey> authority, then the ELF. */
const PROGRAM_DATA_HEADER = 45;

export interface BuildCheck {
    /** sha256 of the deployed ELF without trailing zero padding, as `solana-verify get-program-hash` computes it. */
    hash: string;
    deploySlot: number;
    /** OtterSec verified the source and its executable hash matches `hash`. */
    verified: boolean;
    /** Source registered for verification, if any, as `repo @ commit`. */
    source: string | null;
}

interface OtterStatus {
    is_verified: boolean;
    executable_hash: string;
    repo_url: string;
    commit: string;
}

export async function checkBuild(rpc: RpcClient, programId: string, programData: string): Promise<BuildCheck> {
    const [account, status] = await Promise.all([rpc.getAccountInfo(programData), otterStatus(programId)]);
    if (!account) throw new Error(`ProgramData account ${programData} not found`);
    const data = account.data;
    const deploySlot = Number(new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(4, true));
    let end = data.length;
    while (end > PROGRAM_DATA_HEADER && data[end - 1] === 0) end--;
    const hash = createHash('sha256').update(data.subarray(PROGRAM_DATA_HEADER, end)).digest('hex');
    const repo = status.repo_url.replace(/\/tree\/[0-9a-f]+$/, '');
    return {
        hash,
        deploySlot,
        verified: status.is_verified && status.executable_hash === hash,
        source: repo ? `${repo} @ ${status.commit.slice(0, 7)}` : null,
    };
}

async function otterStatus(programId: string): Promise<OtterStatus> {
    const base = process.env.WATCHTOWER_VERIFY_URL ?? DEFAULT_VERIFY_URL;
    const response = await fetch(`${base}/status/${programId}`, { signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw new Error(`Build verification lookup failed: HTTP ${response.status}`);
    return (await response.json()) as OtterStatus;
}
