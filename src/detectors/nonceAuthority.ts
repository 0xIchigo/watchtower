import { PROGRAMS } from '../constants.js';
import { account, nameOf, pubkeyArg, type ParsedTx } from '../model.js';
import { findingFor, type Detector, type DetectorContext, type Finding } from './types.js';

const ID = 'nonce-authority';

const NONCE_AUTHORITY_ARGS = new Map<string, string>([
    ['initializenonceaccount', 'nonceAuthority'],
    ['authorizenonceaccount', 'newNonceAuthority'],
]);

export const nonceAuthority: Detector = {
    id: ID,
    description: 'Durable nonce accounts created for, or reassigned to, a privileged key',
    detect(tx: ParsedTx, ctx: DetectorContext): Finding[] {
        const findings: Finding[] = [];
        for (const ix of tx.instructions) {
            if (ix.programId !== PROGRAMS.system) continue;
            const name = nameOf(ix);
            const argName = name ? NONCE_AUTHORITY_ARGS.get(name) : undefined;
            const authority = argName ? pubkeyArg(ix, argName) : undefined;
            const key = authority ? ctx.targets.privilegedKeys.get(authority) : undefined;
            if (!key) continue;

            const nonceAccount = account(ix, 'nonce_account')?.pubkey ?? 'unknown';
            const creator = tx.feePayer ?? 'unknown';
            const selfCreated = creator === key.address;
            findings.push(
                findingFor(ID, tx, ix, {
                    severity: selfCreated ? 'medium' : 'high',
                    title:
                        name === 'initializenonceaccount'
                            ? 'Nonce account created for a privileged key'
                            : 'Nonce authority moved to a privileged key',
                    description: selfCreated
                        ? `${key.role} ${key.address} set up durable nonce account ${nonceAccount}. Transactions it signs against this nonce never expire, so a stray signature stays usable indefinitely.`
                        : `${creator} made ${key.role} ${key.address} the authority of durable nonce account ${nonceAccount}. If that key can be tricked into signing a transaction that uses this nonce, the signature never expires and can be submitted at any time.`,
                    subject: key.subject,
                    subjectLabel: key.subjectLabel,
                    details: { 'Nonce account': nonceAccount, Authority: key.address, Role: key.role, 'Created by': creator },
                }),
            );
        }
        return findings;
    },
};
