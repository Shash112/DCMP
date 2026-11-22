import { createHash } from 'crypto';

/**
 * Canonical dcmp-retry-key-v1 fingerprint (Phase 2.1.12 Correction F).
 * Trailing slashes in htu path are preserved by the caller (normalizeHtuFromAbsolute).
 */
export function buildRetryKeyCanonical(input: {
  sessionId: string;
  tokenHash: string;
  proofJti: string;
  proofNonce: string;
  sigHash: string;
  htm: string;
  htu: string;
}): string {
  if (input.htu.includes('?') || input.htu.includes('#')) {
    throw new Error('htu with query/fragment rejected for retry fingerprint');
  }
  return [
    'dcmp-retry-key-v1',
    `session_id=${input.sessionId}`,
    `token_hash=${input.tokenHash}`,
    `proof_jti=${input.proofJti}`,
    `proof_nonce=${input.proofNonce}`,
    `sig_hash=${input.sigHash}`,
    `htm=${input.htm.toUpperCase()}`,
    `htu=${input.htu}`,
    '',
  ].join('\n');
}

export function fingerprintRetryKey(canonical: string): string {
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
