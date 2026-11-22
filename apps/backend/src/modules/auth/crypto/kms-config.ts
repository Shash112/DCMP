/**
 * Phase 2.1.21 — AWS KMS configuration resolution.
 * Three distinct key IDs required for production. Never log key material.
 */

export type AuthCryptoDriver = 'local' | 'kms';

export interface DcmpKmsConfig {
  region: string;
  accessTokenKeyId: string;
  /** Optional previous ECC key ARNs/ids still valid for verify */
  accessTokenVerifyKeyIds: string[];
  ssaHmacKeyId: string;
  /** Optional previous HMAC keys for verify window */
  ssaHmacVerifyKeyIds: string[];
  refreshMasterKeyId: string;
  /** Optional previous CMKs that can Decrypt old data keys */
  refreshMasterVerifyKeyIds: string[];
  endpoint?: string;
}

export function resolveAuthCryptoDriver(): AuthCryptoDriver {
  const raw = (process.env.AUTH_CRYPTO_DRIVER || '').toLowerCase();
  if (raw === 'kms' || raw === 'aws-kms') return 'kms';
  if (raw === 'local') return 'local';
  // Auto: kms when access-token key id configured
  if (process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID) return 'kms';
  return 'local';
}

export function assertLocalCryptoAllowed(driver: AuthCryptoDriver): void {
  const nodeEnv = process.env.NODE_ENV || 'development';
  const allow = process.env.AUTH_ALLOW_LOCAL_KEYS === 'true';
  if (driver === 'local' && nodeEnv === 'production' && !allow) {
    throw new Error(
      'Refusing local crypto providers in production (set AUTH_CRYPTO_DRIVER=kms or AUTH_ALLOW_LOCAL_KEYS for disposable labs only)',
    );
  }
}

export function loadKmsConfig(): DcmpKmsConfig {
  const region =
    process.env.DCMP_KMS_REGION ||
    process.env.AWS_REGION ||
    process.env.AWS_DEFAULT_REGION ||
    'us-east-1';
  const accessTokenKeyId = process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID || '';
  const ssaHmacKeyId = process.env.DCMP_KMS_SSA_HMAC_KEY_ID || '';
  const refreshMasterKeyId = process.env.DCMP_KMS_REFRESH_MASTER_KEY_ID || '';

  if (!accessTokenKeyId || !ssaHmacKeyId || !refreshMasterKeyId) {
    throw new Error(
      'KMS mode requires DCMP_KMS_ACCESS_TOKEN_KEY_ID, DCMP_KMS_SSA_HMAC_KEY_ID, and DCMP_KMS_REFRESH_MASTER_KEY_ID',
    );
  }

  // Refuse accidental reuse of one key for all purposes
  const ids = new Set([accessTokenKeyId, ssaHmacKeyId, refreshMasterKeyId]);
  if (ids.size !== 3) {
    throw new Error(
      'Access-token, SSA HMAC, and refresh CMK identifiers must be three distinct KMS keys',
    );
  }

  const split = (v?: string) =>
    (v || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

  return {
    region,
    accessTokenKeyId,
    accessTokenVerifyKeyIds: split(process.env.DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS),
    ssaHmacKeyId,
    ssaHmacVerifyKeyIds: split(process.env.DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS),
    refreshMasterKeyId,
    refreshMasterVerifyKeyIds: split(process.env.DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS),
    endpoint: process.env.DCMP_KMS_ENDPOINT || undefined,
  };
}

export function isKmsIntegrationConfigured(): boolean {
  try {
    if (resolveAuthCryptoDriver() !== 'kms') return false;
    loadKmsConfig();
    return true;
  } catch {
    return false;
  }
}
