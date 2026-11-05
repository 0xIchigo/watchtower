import { address, getBase58Decoder } from '@solana/kit';
import type { HeliusClient } from 'helius-sdk';
import type { GetProgramAccountsV2Result } from 'helius-sdk/types/types';

interface AccountInfo {
    owner: string;
    lamports: number;
    executable: boolean;
    data: Uint8Array;
}

export interface FungibleHolding {
    mint: string;
    symbol: string | null;
    /** Raw amount. */
    amount: bigint;
    decimals: number;
    usd: number | null;
}

const BASE64 = { encoding: 'base64', commitment: 'confirmed' } as const;

export class RpcClient {
    readonly #helius: HeliusClient;

    constructor(helius: HeliusClient) {
        this.#helius = helius;
    }

    async getAccountInfo(account: string): Promise<AccountInfo | null> {
        const { value } = await this.#helius.getAccountInfo(address(account), BASE64);
        return value
            ? {
                  owner: value.owner,
                  lamports: Number(value.lamports),
                  executable: value.executable,
                  data: Buffer.from(value.data[0] ?? '', 'base64'),
              }
            : null;
    }

    /** Up to 100 addresses per call; `null` where an account does not exist. */
    async getMultipleAccountsData(addresses: string[]): Promise<{ slot: number; data: (Uint8Array | null)[] }> {
        const { context, value } = await this.#helius.getMultipleAccounts(addresses.map(address), BASE64);
        return { slot: Number(context.slot), data: value.map((v) => (v ? Buffer.from(v.data[0] ?? '', 'base64') : null)) };
    }

    async getSlotDurationMs(): Promise<number> {
        const samples = await this.#helius.getRecentPerformanceSamples(10);
        const slots = samples.reduce((sum, s) => sum + Number(s.numSlots), 0);
        const seconds = samples.reduce((sum, s) => sum + s.samplePeriodSecs, 0);
        if (slots === 0) throw new Error('no performance samples');
        return (seconds * 1000) / slots;
    }

    async getSlot(): Promise<number> {
        return Number(await this.#helius.getSlot({ commitment: 'confirmed' }));
    }

    /** Includes native SOL with mint `SOL`. */
    async getFungibleHoldings(owner: string): Promise<FungibleHolding[]> {
        const result = await this.#helius.getAssetsByOwner({
            ownerAddress: owner,
            page: 1,
            limit: 1000,
            displayOptions: { showFungible: true, showNativeBalance: true, showZeroBalance: false },
        });
        const holdings: FungibleHolding[] = result.items.flatMap((item) => {
            const info = item.token_info;
            return info?.balance === undefined
                ? []
                : [
                      {
                          mint: item.id,
                          symbol: info.symbol ?? null,
                          amount: BigInt(info.balance),
                          decimals: info.decimals ?? 0,
                          usd: info.price_info?.total_price ?? null,
                      },
                  ];
        });
        const native = result.nativeBalance;
        if (native && native.lamports > 0) {
            holdings.push({ mint: 'SOL', symbol: 'SOL', amount: BigInt(native.lamports), decimals: 9, usd: native.total_price ?? null });
        }
        return holdings;
    }

    /** `length` bytes at `offset` of each account with the discriminator; `more` is set when over `limit` accounts match. */
    async getAccountSlices(
        programId: string,
        discriminatorHex: string,
        offset: number,
        length: number,
        limit: number,
    ): Promise<{ slices: { pubkey: string; data: Uint8Array }[]; more: boolean }> {
        const response = await this.#helius.getProgramAccountsV2([
            programId,
            {
                encoding: 'base64',
                filters: [{ memcmp: { offset: 0, bytes: getBase58Decoder().decode(Buffer.from(discriminatorHex, 'hex')) } }],
                dataSlice: { offset, length },
                limit,
            },
        ]);
        // Without `withContext`, the result is not wrapped in an RPC context.
        const result = response as GetProgramAccountsV2Result;
        return {
            slices: result.accounts.map((a) => ({
                pubkey: a.pubkey,
                data: Buffer.from((a.account.data as [string, string])[0], 'base64'),
            })),
            more: result.paginationKey !== null,
        };
    }

    /** Balances of the mint's largest token accounts, as UI amounts. */
    async getTokenLargestAccounts(mint: string): Promise<number[]> {
        const { value } = await this.#helius.getTokenLargestAccounts(address(mint), { commitment: 'confirmed' });
        return value.map((a) => a.uiAmount ?? 0);
    }
}
