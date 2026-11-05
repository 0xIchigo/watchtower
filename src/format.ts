export function humanDuration(seconds: number): string {
    if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min`;
    if (seconds < 86_400) return `${Math.round(seconds / 3600)} h`;
    const days = Math.round(seconds / 86_400);
    return days === 1 ? '1 day' : `${days} days`;
}

export function formatAmount(amount: bigint, decimals: number | null): string {
    if (!decimals) return amount.toLocaleString('en-US');
    const scale = 10n ** BigInt(decimals);
    const fraction = (amount % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
    return `${(amount / scale).toLocaleString('en-US')}${fraction ? `.${fraction}` : ''}`;
}

/** UI amount (e.g. `1.5`) to raw units; extra fractional digits beyond `decimals` are dropped. */
export function parseUnits(amount: number, decimals: number): bigint {
    const [whole = '0', fraction = ''] = amount.toFixed(Math.min(decimals, 20)).split('.');
    return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0').slice(0, decimals) || '0');
}

export function toBigInt(value: unknown): bigint | null {
    if (typeof value !== 'string' && typeof value !== 'number') return null;
    try {
        return BigInt(value);
    } catch {
        return null;
    }
}

export function short(address: string): string {
    return `${address.slice(0, 4)}…${address.slice(-4)}`;
}
