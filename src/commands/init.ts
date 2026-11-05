import { existsSync, writeFileSync } from 'node:fs';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { stringify } from 'yaml';
import { endpointsFromEnv, loadEnvFile, MISSING_API_KEY } from '../config.js';
import { writeEnv } from '../configFile.js';
import { discoverMint, discoverProgram, type ProgramState } from '../discover/index.js';
import { ParsedEventsClient } from '../helius/parsedEvents.js';
import { heliusClient } from '../helius/sdk.js';
import { RpcClient } from '../helius/rpc.js';
import { brandBadge, poweredByHelius } from '../style.js';
import { short } from '../format.js';

export interface InitOptions {
    config: string;
    program?: string;
}

const PUBKEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export async function initCommand(options: InitOptions): Promise<void> {
    loadEnvFile();
    p.intro(brandBadge(' Watchtower '));
    const apiKey = process.env.HELIUS_API_KEY;
    if (!apiKey) {
        p.cancel(MISSING_API_KEY);
        process.exitCode = 1;
        return;
    }

    if (existsSync(options.config)) {
        const overwrite = await p.confirm({ message: `${options.config} exists. Overwrite it?`, initialValue: false });
        if (p.isCancel(overwrite) || !overwrite) return cancel();
    }

    const helius = heliusClient(apiKey, endpointsFromEnv());
    const rpc = new RpcClient(helius);
    const events = new ParsedEventsClient(helius, apiKey);

    const programInput =
        options.program ??
        (await p.text({
            message: 'Program ID to monitor',
            placeholder: 'e.g. JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',
            validate: (v) => (v && PUBKEY.test(v.trim()) ? undefined : 'Enter a base58 program ID'),
        }));
    if (p.isCancel(programInput)) return cancel();
    const programId = programInput.trim();
    if (!PUBKEY.test(programId)) {
        p.log.error(`${programInput} is not a base58 program ID`);
        process.exitCode = 1;
        return;
    }

    const spinner = p.spinner();
    spinner.start('Reading the program, its upgrade authority and IDL');
    let program: ProgramState;
    try {
        program = await discoverProgram(rpc, events, programId);
        spinner.stop('Program found');
    } catch (error) {
        spinner.error(pc.red((error as Error).message));
        process.exitCode = 1;
        return;
    }
    p.note(describeProgram(program), 'Discovered');

    const name = await p.text({ message: 'A name for this program (used in alerts)', placeholder: short(program.programId) });
    if (p.isCancel(name)) return cancel();

    let privileged: string[] = [];
    if (program.idl && program.idl.instructions.length > 0) {
        const choice = await p.multiselect({
            message: 'Which instructions are admin-only? Watchtower alerts on every call, and escalates for new signers.',
            options: program.idl.instructions.map((ix) => ({ value: ix, label: ix })),
            initialValues: program.idl.privileged,
            required: false,
        });
        if (p.isCancel(choice)) return cancel();
        privileged = choice;
    }

    const mintInput = await p.text({
        message: 'Token mints to watch too (comma-separated, optional)',
        placeholder: 'leave empty to skip',
        validate: (v) => (!v || v.split(',').every((m) => PUBKEY.test(m.trim())) ? undefined : 'Each mint must be a base58 address'),
    });
    if (p.isCancel(mintInput)) return cancel();
    const mints: string[] = [];
    for (const mint of (mintInput ?? '')
        .split(',')
        .map((m) => m.trim())
        .filter(Boolean)) {
        try {
            await discoverMint(rpc, mint);
            mints.push(mint);
        } catch (error) {
            p.log.warn(`Skipping ${mint}: ${(error as Error).message}`);
        }
    }

    const sinkChoice = await p.multiselect({
        message: 'Where should alerts go? (console is always on)',
        options: [
            { value: 'discord', label: 'Discord webhook' },
            { value: 'slack', label: 'Slack webhook' },
            { value: 'telegram', label: 'Telegram bot' },
            { value: 'webhook', label: 'Generic JSON webhook' },
        ],
        required: false,
    });
    if (p.isCancel(sinkChoice)) return cancel();

    const env: Record<string, string> = {};
    const sinks: Record<string, unknown>[] = [{ type: 'console' }];
    for (const sink of sinkChoice) {
        if (sink === 'telegram') {
            const botToken = await p.password({ message: 'Telegram bot token' });
            const chatId = await p.text({ message: 'Telegram chat ID' });
            if (p.isCancel(botToken) || p.isCancel(chatId)) return cancel();
            env.TELEGRAM_BOT_TOKEN = botToken;
            env.TELEGRAM_CHAT_ID = chatId;
            sinks.push({ type: 'telegram', botToken: '${TELEGRAM_BOT_TOKEN}', chatId: '${TELEGRAM_CHAT_ID}', minSeverity: 'medium' });
            continue;
        }
        const url = await p.password({ message: `${sink[0]!.toUpperCase()}${sink.slice(1)} webhook URL` });
        if (p.isCancel(url)) return cancel();
        const variable = `${sink.toUpperCase()}_WEBHOOK_URL`;
        env[variable] = url;
        sinks.push({ type: sink, url: `\${${variable}}`, minSeverity: 'medium' });
    }

    const config = {
        programs: [
            {
                id: program.programId,
                ...(name ? { name } : {}),
                privilegedInstructions: privileged,
            },
        ],
        multisigs: [],
        mints: mints.map((address) => ({ address })),
        alerts: { minSeverity: 'low', sinks },
        backfill: { lookbackDays: 90, maxScannedTransactions: 50_000 },
    };
    writeFileSync(
        options.config,
        `# Generated by \`watchtower init\`. See watchtower.example.yaml for every option.\n${stringify(config)}`,
    );
    writeEnv(env);

    p.note(
        [
            `${pc.bold(options.config)} written${Object.keys(env).length > 0 ? `; channel secrets added to ${pc.bold('.env')}` : ''}.`,
            '',
            `${pc.cyan('watchtower report')}   security posture plus ${config.backfill.lookbackDays} days of history`,
            `${pc.cyan('watchtower watch')}    live alerts from Parsed Streams`,
        ].join('\n'),
        'Next',
    );
    p.outro(poweredByHelius());
}

function describeProgram(program: ProgramState): string {
    const lines = [`Program data   ${program.programData}`];
    switch (program.authorityKind) {
        case 'immutable':
            lines.push(`Authority      ${pc.green('none (immutable)')}`);
            break;
        case 'wallet':
            lines.push(`Authority      ${program.upgradeAuthority} ${pc.red('(single wallet)')}`);
            break;
        case 'unknown-pda':
            lines.push(`Authority      ${program.upgradeAuthority} ${pc.yellow('(PDA, not a Squads vault)')}`);
            break;
        case 'squads': {
            const m = program.multisig!;
            lines.push(`Authority      Squads v${m.version} vault ${program.upgradeAuthority}`);
            lines.push(`Multisig       ${m.address}`);
            lines.push(
                `Threshold      ${m.threshold} of ${m.members.length}${m.version === 4 ? `, time lock ${m.timeLockSeconds}s` : ', no time lock (v3)'}`,
            );
            break;
        }
    }
    lines.push(`Last deployed  slot ${program.lastDeploySlot.toLocaleString('en-US')}`);
    lines.push(`IDL            ${program.idl ? `${program.idl.instructions.length} instructions` : pc.dim('not found')}`);
    return lines.join('\n');
}

function cancel(): void {
    p.cancel('Cancelled');
    process.exitCode = 1;
}
