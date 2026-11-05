import type { WatchTargets } from './detectors/types.js';
import { summarizeIdl } from './discover/idl.js';
import type { AlertMode, Engine } from './engine.js';
import type { ParsedEventsClient } from './helius/parsedEvents.js';
import type { StateStore } from './state.js';

const ID = 'idl-change';

/** Returns the number of new findings. The first check per program only records a baseline. */
export async function checkIdlChanges(
    events: ParsedEventsClient,
    engine: Engine,
    state: StateStore,
    targets: WatchTargets,
    mode: AlertMode,
): Promise<number> {
    let found = 0;
    for (const program of targets.programs.values()) {
        const versions = await events.listIdlVersions(program.id);
        const latest = versions.at(-1);
        const previousSlot = state.idlVersion(program.id);
        if (!latest || latest.slot === previousSlot) continue;
        if (previousSlot === undefined) {
            state.setIdlVersion(program.id, latest.slot);
            continue;
        }

        const [before, after] = await Promise.all([
            events.getIdl(program.id, previousSlot).then(summarizeIdl),
            events.getIdl(program.id, latest.slot).then(summarizeIdl),
        ]);
        const added = after.instructions.filter((ix) => !before.instructions.includes(ix));
        const removed = before.instructions.filter((ix) => !after.instructions.includes(ix));
        const newAdmin = added.filter((ix) => after.privileged.includes(ix));
        const changes = [
            added.length > 0 ? `added ${added.join(', ')}` : '',
            removed.length > 0 ? `removed ${removed.join(', ')}` : '',
        ].filter(Boolean);

        const recorded = await engine.record(
            {
                id: `${ID}:${program.id}:${latest.slot}`,
                detector: ID,
                severity: newAdmin.length > 0 ? 'high' : 'medium',
                title: newAdmin.length > 0 ? 'New admin instruction in IDL' : 'IDL updated',
                description: `${program.label} published a new IDL${changes.length > 0 ? `: ${changes.join('; ')}` : ' with no instruction changes'}.`,
                subject: program.id,
                subjectLabel: program.label,
                signature: null,
                slot: latest.slot,
                blockTime: null,
                details: {
                    'Previous version': `slot ${previousSlot}`,
                    'New version': `slot ${latest.slot} (${latest.sources.join(', ')})`,
                    ...(newAdmin.length > 0 ? { 'New admin-looking instructions': newAdmin.join(', ') } : {}),
                },
            },
            mode,
        );
        // Only once recorded, so a failed fetch is retried on the next poll.
        state.setIdlVersion(program.id, latest.slot);
        if (recorded) found++;
    }
    state.save();
    return found;
}
