import { PROGRAMS } from '../constants.js';
import { nameOf, type ParsedTx } from '../model.js';

export function usesDurableNonce(tx: ParsedTx): boolean {
    const first = tx.instructions[0];
    return first?.programId === PROGRAMS.system && nameOf(first) === 'advancenonceaccount';
}
