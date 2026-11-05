import type { Finding } from './detectors/types.js';
import { checkBuild } from './discover/build.js';
import { discoverMint } from './discover/index.js';
import { humanDuration } from './format.js';
import type { ParsedEventsClient } from './helius/parsedEvents.js';
import type { RpcClient } from './helius/rpc.js';

const YOUNG_TOKEN_SECONDS = 30 * 86_400;
const CONCENTRATED_TOP_10_SHARE = 0.9;
const YOUNG_ADMIN_SECONDS = 7 * 86_400;

export function createEnricher(
    rpc: RpcClient,
    events: ParsedEventsClient,
    programDataOf: (programId: string) => string | null,
): (finding: Finding) => Promise<void> {
    const firstSeen = new Map<string, Promise<number | null>>();
    const flaggedSigners = new Set<string>();
    const firstSeenAt = (address: string) => {
        if (!firstSeen.has(address)) {
            const lookup = events
                .transactionHistory({ address, sortOrder: 'asc', limit: 1 })
                .then((page) => page.data[0]?.parsed?.blockTime ?? null);
            lookup.catch(() => firstSeen.delete(address));
            firstSeen.set(address, lookup);
        }
        return firstSeen.get(address)!;
    };
    return async (finding) => {
        if (finding.details['Listed mint']) await vetListing(rpc, firstSeenAt, finding);
        if (finding.details['Admin signer']) await vetAdminSigner(firstSeenAt, finding, flaggedSigners);
        const programData =
            finding.detector === 'program-deployment' && finding.title === 'Program upgraded' ? programDataOf(finding.subject) : null;
        if (programData) await vetUpgrade((id) => checkBuild(rpc, id, programData), finding);
    };
}

export async function vetUpgrade(check: (programId: string) => ReturnType<typeof checkBuild>, finding: Finding): Promise<void> {
    try {
        const build = await check(finding.subject);
        if (build.deploySlot !== finding.slot) {
            finding.details['Verified build'] = 'Not checked: a later deployment replaced this bytecode';
            return;
        }
        finding.details['Bytecode hash'] = build.hash;
        if (build.verified) {
            finding.details['Verified build'] = `Yes, ${build.source}`;
            finding.description += ` The new bytecode matches its verified build (${build.source}).`;
            return;
        }
        finding.details['Verified build'] = build.source ? `No: not ${build.source}` : 'No: the program has no verified build';
        finding.description += build.source
            ? ` The new bytecode does not match the verified build ${build.source}; it may simply not be verified yet.`
            : ' The program has no verified build, so the new bytecode cannot be matched to source.';
    } catch (error) {
        finding.details['Verified build'] = `Could not check: ${(error as Error).message}`;
    }
}

type FirstSeen = (address: string) => Promise<number | null>;

export async function vetListing(rpc: RpcClient, firstSeenAt: FirstSeen, finding: Finding): Promise<void> {
    const mint = finding.details['Listed mint']!;
    const reasons: string[] = [];
    const controls: string[] = [];
    try {
        const [createdAt, info, largest] = await Promise.all([
            firstSeenAt(mint),
            discoverMint(rpc, mint),
            rpc.getTokenLargestAccounts(mint),
        ]);
        if (createdAt !== null) {
            const age = (finding.blockTime ?? Date.now() / 1000) - createdAt;
            finding.details['Token age at listing'] = humanDuration(age);
            if (age < YOUNG_TOKEN_SECONDS) reasons.push(`it was created only ${humanDuration(age)} before this listing`);
        }
        const supply = Number(info.supply) / 10 ** info.decimals;
        if (supply > 0) {
            const share = largest.slice(0, 10).reduce((sum, amount) => sum + amount, 0) / supply;
            finding.details['Top 10 holders now'] = `${(share * 100).toFixed(1)}% of supply`;
            // Holdings are read now, so they only describe a listing from the last day.
            const recent = finding.blockTime === null || Date.now() / 1000 - finding.blockTime < 86_400;
            if (recent && share >= CONCENTRATED_TOP_10_SHARE) reasons.push(`its top 10 holders own ${(share * 100).toFixed(0)}% of supply`);
        }
        finding.details['Mint authority'] = info.mintAuthority ?? 'revoked';
        if (info.freezeAuthority) controls.push(`${info.freezeAuthority} can freeze any holder's account`);
        for (const control of info.controls) controls.push(`${control.extension.toLowerCase()}: ${control.text}`);
        const critical = info.controls.filter((c) => c.severity === 'critical');
        if (critical.length > 0) reasons.push(`it carries ${critical.map((c) => c.extension.toLowerCase()).join(' and ')}`);
    } catch (error) {
        finding.details.Vetting = `Could not vet the listed token: ${(error as Error).message}`;
        return;
    }
    if (controls.length > 0) finding.details['Token controls'] = controls.join('; ');
    if (reasons.length > 0) {
        finding.severity = 'critical';
        finding.description += ` The listed token is risky as collateral: ${reasons.join(' and ')}.`;
    }
}

/** Only the first call per young signer is escalated; later ones still get the `control` stage. */
export async function vetAdminSigner(firstSeenAt: FirstSeen, finding: Finding, flagged: Set<string>): Promise<void> {
    const signer = finding.details['Admin signer']!;
    try {
        const createdAt = await firstSeenAt(signer);
        if (createdAt === null) return;
        const age = (finding.blockTime ?? Date.now() / 1000) - createdAt;
        const ageText = humanDuration(Math.max(age, 60));
        finding.details['Admin signer age'] = ageText;
        if (age >= YOUNG_ADMIN_SECONDS) return;
        finding.stages = [...new Set([...(finding.stages ?? []), 'control' as const])];
        if (flagged.has(signer)) return;
        flagged.add(signer);
        finding.severity = 'critical';
        finding.title = `Admin call from a new wallet: ${finding.title}`;
        finding.description += ` It was signed by ${signer}, which first appeared on-chain ${ageText} earlier.`;
    } catch (error) {
        finding.details.Vetting = `Could not check the admin signer's age: ${(error as Error).message}`;
    }
}
