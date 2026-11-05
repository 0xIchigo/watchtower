// Checks a `replay --json` of the Drift exploit window (2026-03-20 to 2026-04-02) for the alerts Watchtower must raise
// on the new admin's first admin transaction. Exits 1, listing what is missing, so CI fails when detection regresses.
//   node scripts/check-drift-replay.mjs reports/drift-replay.json
import { readFileSync } from 'node:fs';

const FIRST_ADMIN_TX = '4a5962Rdqd9pkXtk9DMQ9ZYhdGb2k9gPw71GvukJgELhxbCY5gm1c1hhKdwuGefyqJ3XMvihUTDNDn3qbXnst82X';

const EXPECTED = [
    { detector: 'attack-chain', title: 'Possible attack in progress' },
    { detector: 'privileged-instruction', title: 'Admin call from a new wallet: New market or asset added: initialize_spot_market' },
];

const path = process.argv[2];
if (!path) {
    console.error('Usage: node scripts/check-drift-replay.mjs <replay.json>');
    process.exit(2);
}
const { findings } = JSON.parse(readFileSync(path, 'utf8'));
const onFirstTx = findings.filter((f) => f.signature === FIRST_ADMIN_TX && f.severity === 'critical');
const missing = EXPECTED.filter((e) => !onFirstTx.some((f) => f.detector === e.detector && f.title === e.title));

if (missing.length > 0) {
    console.error(`Drift replay regressed: ${missing.length} expected critical alert(s) missing on ${FIRST_ADMIN_TX.slice(0, 12)}…`);
    for (const e of missing) console.error(`  missing: [${e.detector}] ${e.title}`);
    console.error(`Critical alerts found on that transaction: ${onFirstTx.map((f) => `[${f.detector}] ${f.title}`).join('; ') || 'none'}`);
    console.error(`Findings in the window: ${findings.length}`);
    process.exit(1);
}
console.log(
    `Drift replay OK: ${EXPECTED.length} critical alerts on the new admin's first transaction (${findings.length} findings in the window).`,
);
