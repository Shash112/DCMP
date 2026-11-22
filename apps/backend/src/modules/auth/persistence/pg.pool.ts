import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool, PoolClient } from 'pg';

export const PG_POOL = Symbol('PG_POOL');

/**
 * Disposable validation pool targeting EDB PostgreSQL 16 on 127.0.0.1:55432.
 * Never points at PostgreSQL 18 or production.
 */
@Injectable()
export class ValidationPgPool implements OnModuleDestroy {
  readonly pool: Pool;

  constructor() {
    const host = process.env.DCMP_VALIDATION_PGHOST || '127.0.0.1';
    const port = parseInt(process.env.DCMP_VALIDATION_PGPORT || '55432', 10);
    const database = process.env.DCMP_VALIDATION_PGDATABASE || 'dcmp_validation';
    const user = process.env.DCMP_VALIDATION_PGUSER || 'dcmp_val_super';
    if (port === 5432 || port === 5433) {
      // Soft guard: common PG18/default ports — refuse unless explicitly overridden
      if (process.env.DCMP_ALLOW_NON_VALIDATION_PORT !== 'true') {
        throw new Error(
          `Refusing to connect on port ${port}; expected validation port 55432 (set DCMP_ALLOW_NON_VALIDATION_PORT to override)`,
        );
      }
    }
    this.pool = new Pool({
      host,
      port,
      database,
      user,
      max: 10,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
    });
  }

  async withAppClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('SET SESSION AUTHORIZATION dcmp_app');
      return await fn(client);
    } finally {
      try {
        await client.query('RESET SESSION AUTHORIZATION');
      } catch {
        /* ignore */
      }
      client.release();
    }
  }

  /**
   * Transaction with tenant GUC set LOCAL — cannot leak to other pool users.
   */
  async withTenantTx<T>(
    organizationId: string,
    fn: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    return this.withAppClient(async (client) => {
      await client.query('BEGIN');
      try {
        await client.query(
          `SELECT set_config('app.current_organization_id', $1, true)`,
          [organizationId],
        );
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
      } catch (e) {
        try {
          await client.query('ROLLBACK');
        } catch {
          /* ignore */
        }
        throw e;
      }
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}
