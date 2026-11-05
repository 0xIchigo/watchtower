export const PROGRAMS = {
    system: '11111111111111111111111111111111',
    bpfLoaderUpgradeable: 'BPFLoaderUpgradeab1e11111111111111111111111',
    splToken: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    token2022: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
    squadsV4: 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf',
    squadsV3: 'SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu',
    stake: 'Stake11111111111111111111111111111111111111',
} as const;

export const SQUADS_PROGRAMS: readonly string[] = [PROGRAMS.squadsV4, PROGRAMS.squadsV3];

export const VERSION = '0.1.0';

/** Sent as `X-Helius-Client` with every Helius request. */
export const CLIENT_ID = `helius-watchtower/${VERSION}`;

/** Used only when the RPC cannot report recent slot times. */
export const FALLBACK_SLOT_MS = 400;
