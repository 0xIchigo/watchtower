import pc from 'picocolors';
import { loadConfig } from '../config.js';
import { Monitor, type LogLevel } from '../monitor.js';
import { poweredByHelius } from '../style.js';

export interface WatchOptions {
    config: string;
    backfill: boolean;
}

const LEVEL_COLOR: Record<LogLevel, (text: string) => string> = {
    info: (t) => t,
    success: pc.green,
    warn: pc.yellow,
    error: pc.red,
    detail: pc.dim,
};

export async function watchCommand(options: WatchOptions): Promise<void> {
    const monitor = new Monitor(loadConfig(options.config), { backfill: options.backfill });
    monitor.on('log', (level, message) => log(LEVEL_COLOR[level](message)));
    log(`${pc.bold('Watchtower')} ${poweredByHelius()}`);

    const shutdown = async () => {
        log('Shutting down…');
        await monitor.stop();
        process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);

    await monitor.start();
}

function log(message: string): void {
    console.log(`${pc.dim(new Date().toISOString().slice(11, 19))} ${message}`);
}
