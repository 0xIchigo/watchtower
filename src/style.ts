import pc from 'picocolors';

export const HELIUS_ICON_URL = 'https://www.helius.dev/Helius-Brandkit/Helius/PNG/Helius-Icon.png';

/** Helius brand orange, #E84326. */
export function brand(text: string): string {
    return pc.isColorSupported ? `\x1b[38;2;232;67;38m${text}\x1b[39m` : text;
}

export function brandBadge(text: string): string {
    return pc.isColorSupported ? `\x1b[48;2;232;67;38m\x1b[38;2;255;255;255m${text}\x1b[39m\x1b[49m` : text;
}

export function poweredByHelius(): string {
    return `${pc.dim('Powered by')} ${brand('Helius')}`;
}
