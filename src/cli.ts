#!/usr/bin/env node
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { initCommand } from './commands/init.js';
import { replayCommand } from './commands/replay.js';
import { reportCommand } from './commands/report.js';
import { serveCommand } from './commands/serve.js';
import { testAlertCommand } from './commands/testAlert.js';
import { watchCommand } from './commands/watch.js';
import { DEFAULT_CONFIG_PATH, SEVERITIES } from './config.js';
import { VERSION } from './constants.js';

const program = new Command()
    .name('watchtower')
    .description('Security monitoring for Solana programs, powered by Helius Parsed Events and Parsed Streams')
    .version(VERSION);

program
    .command('init')
    .description('Set up watchtower.yaml for a program: finds its upgrade authority, multisig and admin instructions')
    .option('-c, --config <path>', 'config file to write', DEFAULT_CONFIG_PATH)
    .option('--program <id>', 'program ID (otherwise a prompt)')
    .action(run(initCommand));

program
    .command('report')
    .description('Grade the security posture of watched programs and scan their history with Parsed Events')
    .option('-c, --config <path>', 'config file', DEFAULT_CONFIG_PATH)
    .option('--html <path>', 'where to write the HTML report (default reports/watchtower-<date>.html)')
    .option('--no-html', 'skip the HTML report')
    .option('--json <path>', 'also write the report as JSON')
    .action(run(reportCommand));

program
    .command('watch')
    .description('Stream live alerts with Parsed Streams, filling any downtime gap with Parsed Events')
    .option('-c, --config <path>', 'config file', DEFAULT_CONFIG_PATH)
    .option('--no-backfill', 'skip the gap-fill scan on connect')
    .action(run(watchCommand));

program
    .command('serve')
    .description('Run the web dashboard: set up monitoring in the browser and watch findings live')
    .option('-c, --config <path>', 'config file', DEFAULT_CONFIG_PATH)
    .option('--host <host>', 'interface to bind (default 127.0.0.1, or HOST)')
    .option('--port <port>', 'port (default 4545, or PORT)')
    .option('--no-backfill', 'skip the gap-fill scan on connect')
    .action(run(serveCommand));

program
    .command('replay')
    .description('Run every detector over a past window with Parsed Events, e.g. to see what an exploit would have triggered')
    .requiredOption('--from <date|slot>', 'window start: a date such as 2026-03-20, or a slot')
    .requiredOption('--to <date|slot>', 'window end')
    .option('-c, --config <path>', 'config file (ignored with --program)', DEFAULT_CONFIG_PATH)
    .option(
        '--program <programs...>',
        'replay these programs (id or id:Name) instead of the config; admin instructions come from their IDLs',
    )
    .option('--budget <n>', 'max transactions scanned per scan plan', '500000')
    .option('--no-program-scans', "skip scanning busy programs' whole history; admin keys, multisigs, mints and vaults are still scanned")
    .addOption(new Option('--min-severity <level>', 'lowest severity to print').choices([...SEVERITIES]).default('medium'))
    .option('--json <path>', 'also write the findings as JSON')
    .action(run(replayCommand));

program
    .command('test-alert')
    .description('Send a sample alert to every configured channel')
    .option('-c, --config <path>', 'config file', DEFAULT_CONFIG_PATH)
    .action(run(testAlertCommand));

function run<T>(command: (options: T) => Promise<void>): (options: T) => Promise<void> {
    return async (options) => {
        try {
            await command(options);
        } catch (error) {
            console.error(pc.red(`\n${(error as Error).message}`));
            process.exitCode = 1;
        }
    };
}

await program.parseAsync();
