import pc from 'picocolors';
import { loadEnvFile } from '../config.js';
import { WatchtowerServer, type ServerOptions } from '../server/index.js';
import { poweredByHelius } from '../style.js';

export interface ServeOptions {
    config: string;
    host?: string;
    port?: string;
    backfill: boolean;
}

const DEFAULT_PORT = 4545;
const PORT_ATTEMPTS = 10;

export async function serveCommand(options: ServeOptions): Promise<void> {
    loadEnvFile();
    const readOnly = /^(1|true|yes)$/i.test(process.env.WATCHTOWER_READONLY ?? '');
    const requestedPort = options.port ?? process.env.PORT;
    const base: Omit<ServerOptions, 'port'> = {
        host: options.host ?? process.env.HOST ?? '127.0.0.1',
        configPath: options.config,
        backfill: options.backfill,
        password: process.env.WATCHTOWER_PASSWORD || undefined,
        readOnly,
    };

    const ports = requestedPort ? [Number(requestedPort)] : Array.from({ length: PORT_ATTEMPTS }, (_, i) => DEFAULT_PORT + i);
    let started: Awaited<ReturnType<WatchtowerServer['listen']>> | undefined;
    for (const port of ports) {
        try {
            started = await new WatchtowerServer({ ...base, port }).listen();
            break;
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw error;
            if (requestedPort) {
                throw new Error(
                    `Port ${port} is already in use. Stop whatever is using it (\`lsof -i :${port}\`) or choose another with --port.`,
                );
            }
            console.log(pc.yellow(`Port ${port} is in use, trying ${port + 1}…`));
        }
    }
    if (!started) throw new Error(`Ports ${ports[0]}–${ports.at(-1)} are all in use. Choose a free one with --port.`);

    console.log(
        `${pc.bold('Watchtower')} dashboard on ${pc.cyan(started.url)}${readOnly ? pc.dim(' (read-only)') : ''}  ${poweredByHelius()}`,
    );
    if (!process.env.HELIUS_API_KEY)
        console.log(pc.yellow('No HELIUS_API_KEY yet: copy .env.example to .env, add your key, then click Recheck in the dashboard.'));

    const close = started.close;
    const shutdown = async () => {
        await close();
        process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
}
