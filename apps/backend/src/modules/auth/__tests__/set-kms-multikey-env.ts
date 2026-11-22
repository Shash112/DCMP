/**
 * Phase 2.1.24 — Live multi-key KMS env (extends 2.1.22 harness).
 *
 * Prior key IDs MUST be supplied via environment (not hardcoded here):
 *   DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID
 *   DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID
 *   DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID
 *
 * Active keys remain the original non-prod IDs (same defaults as set-kms-redis-postgres-env).
 * VERIFY lists are set to the prior keys for rotation grace.
 */
process.env.AUTH_CRYPTO_DRIVER = 'kms';
process.env.AUTH_STORE_DRIVER = 'postgres';
process.env.AUTH_REDIS_DRIVER = 'real';
process.env.AUTH_REDIS_REQUIRED = 'true';

process.env.AWS_PROFILE = process.env.AWS_PROFILE || 'dcmp-nonprod';
process.env.AWS_REGION = process.env.AWS_REGION || 'ap-south-1';
process.env.DCMP_KMS_REGION = process.env.DCMP_KMS_REGION || process.env.AWS_REGION;

process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID =
  process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID || '802a81e6-3f7c-4a07-a15b-57b8ab506bfd';
process.env.DCMP_KMS_SSA_HMAC_KEY_ID =
  process.env.DCMP_KMS_SSA_HMAC_KEY_ID || '5a88e3e7-0732-466b-8df6-2c9885ddfdaa';
process.env.DCMP_KMS_REFRESH_MASTER_KEY_ID =
  process.env.DCMP_KMS_REFRESH_MASTER_KEY_ID || '8287866f-d8be-4c73-8372-aa24b78357d5';

const priorAt = process.env.DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID;
const priorSsa = process.env.DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID;
const priorRefresh = process.env.DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID;

if (!priorAt || !priorSsa || !priorRefresh) {
  throw new Error(
    'Phase 2.1.24 requires DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID, DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID, and DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID',
  );
}

// Active = originals. Prior keys for verify / unwrap grace (from env only).
process.env.DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS = priorAt;
process.env.DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS = priorSsa;
process.env.DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS = priorRefresh;

process.env.REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
process.env.REDIS_PORT = process.env.REDIS_PORT || '6379';
process.env.REDIS_DB = process.env.REDIS_DB || '15';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
delete process.env.AUTH_ALLOW_LOCAL_KEYS;

process.env.DCMP_VALIDATION_PGHOST = process.env.DCMP_VALIDATION_PGHOST || '127.0.0.1';
process.env.DCMP_VALIDATION_PGPORT = process.env.DCMP_VALIDATION_PGPORT || '55432';
process.env.DCMP_VALIDATION_PGDATABASE =
  process.env.DCMP_VALIDATION_PGDATABASE || 'dcmp_validation';
process.env.DCMP_VALIDATION_PGUSER = process.env.DCMP_VALIDATION_PGUSER || 'dcmp_val_super';
delete process.env.DCMP_PUBLIC_ORIGIN;
