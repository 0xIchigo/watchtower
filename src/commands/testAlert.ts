import pc from 'picocolors';
import { loadConfig } from '../config.js';
import type { Finding } from '../detectors/types.js';
import { createSinks, dispatch } from '../sinks.js';

export async function testAlertCommand(options: { config: string }): Promise<void> {
    const config = loadConfig(options.config);
    const program = config.programs[0]!;
    const sample: Finding = {
        id: 'test',
        detector: 'test-alert',
        severity: 'critical',
        title: 'Test alert',
        description: `Watchtower can reach this channel. Real alerts for ${program.name ?? program.id} will look like this.`,
        subject: program.id,
        subjectLabel: program.name ?? program.id,
        signature: '1111111111111111111111111111111111111111111111111111111111111111',
        slot: 0,
        blockTime: Math.floor(Date.now() / 1000),
        details: { 'Executed via': 'Squads multisig (example)', Authority: program.id },
    };
    const sinks = createSinks(config.alerts.sinks, 'info');
    await dispatch(sinks, sample);
    console.log(pc.green(`\nSent a test alert to: ${sinks.map((s) => s.name).join(', ')}`));
}
