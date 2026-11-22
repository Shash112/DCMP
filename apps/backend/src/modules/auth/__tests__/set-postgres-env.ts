/**
 * Must be loaded via `node --import` BEFORE AuthModule evaluates AUTH_STORE_DRIVER.
 */
process.env.AUTH_STORE_DRIVER = 'postgres';
process.env.NODE_ENV = 'test';
process.env.AUTH_ALLOW_LOCAL_KEYS = 'true';
process.env.DCMP_VALIDATION_PGHOST = process.env.DCMP_VALIDATION_PGHOST || '127.0.0.1';
process.env.DCMP_VALIDATION_PGPORT = process.env.DCMP_VALIDATION_PGPORT || '55432';
process.env.DCMP_VALIDATION_PGDATABASE = process.env.DCMP_VALIDATION_PGDATABASE || 'dcmp_validation';
process.env.DCMP_VALIDATION_PGUSER = process.env.DCMP_VALIDATION_PGUSER || 'dcmp_val_super';
delete process.env.DCMP_PUBLIC_ORIGIN;
