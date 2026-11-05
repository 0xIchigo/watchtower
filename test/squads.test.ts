import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { summarizeIdl } from '../src/discover/idl.js';
import { decodeMultisig, findVaultIndex } from '../src/discover/squads.js';

function fixture(name: string): { address: string; owner: string; data: Uint8Array } {
    const raw = JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
    return { address: raw.address, owner: raw.owner, data: Buffer.from(raw.data, 'base64') };
}

describe('Squads multisig decoding (mainnet accounts)', () => {
    it('decodes a v4 multisig and finds the vault that is Kamino Lend’s upgrade authority', async () => {
        const account = fixture('kamino-squads-v4.json');
        const multisig = decodeMultisig(account.address, account.owner, account.data);
        expect(multisig).toMatchObject({
            version: 4,
            threshold: 5,
            timeLockSeconds: 86_400,
            configAuthority: null,
        });
        expect(multisig!.members).toHaveLength(10);
        expect(await findVaultIndex(4, account.address, 'GzFgdRJXmawPhGeBsyRCDLx4jAKPsvbUqoqitzppkzkW')).toBe(0);
    });

    it('decodes a v3 multisig and finds the authority that is Jupiter v6’s upgrade authority', async () => {
        const account = fixture('jupiter-squads-v3.json');
        const multisig = decodeMultisig(account.address, account.owner, account.data);
        expect(multisig).toMatchObject({ version: 3, threshold: 4, timeLockSeconds: 0, configAuthority: null });
        expect(multisig!.members).toHaveLength(7);
        expect(await findVaultIndex(3, account.address, 'CvQZZ23qYDWF2RUpxYJ8y9K4skmuvYEEjH7fK58jtipQ')).toBe(1);
    });

    it('rejects accounts that are not Squads multisigs', () => {
        const account = fixture('kamino-squads-v4.json');
        expect(decodeMultisig(account.address, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', account.data)).toBeNull();
    });
});

describe('admin instruction heuristic (mainnet IDLs)', () => {
    const idl = (name: string) => summarizeIdl(JSON.parse(readFileSync(new URL(`./fixtures/idl-${name}.json`, import.meta.url), 'utf8')));

    it('flags Kamino Lend market, reserve and global-config admin instructions but not user flows', () => {
        const { privileged } = idl('kamino');
        expect(privileged).toEqual(
            expect.arrayContaining([
                'updateLendingMarket',
                'updateLendingMarketOwner',
                'updateReserveConfig',
                'updateGlobalConfigAdmin',
                'socializeLoss',
            ]),
        );
        for (const user of [
            'depositReserveLiquidity',
            'borrowObligationLiquidity',
            'setBorrowOrder',
            'updateObligationConfig',
            'initUserMetadata',
        ]) {
            expect(privileged).not.toContain(user);
        }
    });

    it('flags only Jupiter v6 operator instructions', () => {
        expect(idl('jupiter').privileged).toEqual(['close_token', 'withdraw_token_account_excess_lamports']);
    });
});
