/**
 * Phase 2.1.22 — load BEFORE AuthModule evaluates AUTH_CRYPTO_DRIVER.
 * Live non-prod AWS KMS + real Redis + PostgreSQL 16.10 validation DB.
 *
 * Does NOT set AUTH_ALLOW_LOCAL_KEYS.
 * Does NOT hardcode AWS access keys — uses AWS SDK default chain (AWS_PROFILE).
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

process.env.REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
process.env.REDIS_PORT = process.env.REDIS_PORT || '6379';
process.env.REDIS_DB = process.env.REDIS_DB || '15';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
// Explicitly refuse local-key override for this harness
delete process.env.AUTH_ALLOW_LOCAL_KEYS;

process.env.DCMP_VALIDATION_PGHOST = process.env.DCMP_VALIDATION_PGHOST || '127.0.0.1';
process.env.DCMP_VALIDATION_PGPORT = process.env.DCMP_VALIDATION_PGPORT || '55432';
process.env.DCMP_VALIDATION_PGDATABASE =
  process.env.DCMP_VALIDATION_PGDATABASE || 'dcmp_validation';
process.env.DCMP_VALIDATION_PGUSER = process.env.DCMP_VALIDATION_PGUSER || 'dcmp_val_super';
delete process.env.DCMP_PUBLIC_ORIGIN;
