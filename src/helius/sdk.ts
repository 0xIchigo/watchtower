import { createHelius, type HeliusClient } from 'helius-sdk';
import { CLIENT_ID } from '../constants.js';
import type { Config } from '../config.js';

export function heliusClient(apiKey: string, endpoints: Config['endpoints']): HeliusClient {
    return createHelius({ apiKey, userAgent: CLIENT_ID, ...(endpoints.rpc ? { baseUrl: endpoints.rpc } : {}) });
}
