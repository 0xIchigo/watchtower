import { SEVERITIES, severityRank, type Severity } from '../config.js';

export function maxSeverity(...severities: Severity[]): Severity {
    return severities.reduce((a, b) => (severityRank(b) > severityRank(a) ? b : a));
}

export function escalate(severity: Severity): Severity {
    return SEVERITIES[Math.min(severityRank(severity) + 1, SEVERITIES.length - 1)]!;
}
