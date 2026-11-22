/**
 * Phase 2.1.25 / 2.1.25.1 — fail-closed crypto test/rotation drill hooks.
 * Allowed ONLY when NODE_ENV === 'test'. No environment variable may override.
 */
export function assertCryptoTestHooksAllowed(): void {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('Crypto test hooks are disabled outside test mode');
  }
}
