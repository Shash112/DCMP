/**
 * Phase 2.1.20 — load BEFORE AuthModule evaluates drivers.
 * Real Redis (dcmp-redis :6379) + PostgreSQL 16.10 validation DB :55432.
 */
process.env.AUTH_STORE_DRIVER = 'postgres';
process.env.AUTH_REDIS_DRIVER = 'real';
process.env.AUTH_REDIS_REQUIRED = 'true';
process.env.REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
process.env.REDIS_PORT = process.env.REDIS_PORT || '6379';
process.env.REDIS_DB = process.env.REDIS_DB || '15'; // isolated test DB index
process.env.NODE_ENV = 'test';
process.env.AUTH_ALLOW_LOCAL_KEYS = 'true';
process.env.DCMP_VALIDATION_PGHOST = process.env.DCMP_VALIDATION_PGHOST || '127.0.0.1';
process.env.DCMP_VALIDATION_PGPORT = process.env.DCMP_VALIDATION_PGPORT || '55432';
process.env.DCMP_VALIDATION_PGDATABASE =
  process.env.DCMP_VALIDATION_PGDATABASE || 'dcmp_validation';
process.env.DCMP_VALIDATION_PGUSER = process.env.DCMP_VALIDATION_PGUSER || 'dcmp_val_super';
delete process.env.DCMP_PUBLIC_ORIGIN;
