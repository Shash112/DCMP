import { Inject, Injectable } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { AUTH_REDIS, AuthRedisPort } from '../auth/redis/redis.port';
import { ValidationPgPool } from '../auth/persistence/pg.pool';

export interface HealthCheckResult {
  status: 'ok' | 'degraded' | 'down';
  service: string;
  version: string;
  timestamp: string;
  environment: string;
  uptimeSeconds: number;
}

export interface ReadinessResult {
  ready: boolean;
  checks: {
    postgres?: { ok: boolean; detail?: string };
    redis?: { ok: boolean; mode?: string; detail?: string };
  };
  timestamp: string;
}

@Injectable()
export class HealthService {
  private readonly startTime = Date.now();

  constructor(@Inject(ModuleRef) private readonly moduleRef: ModuleRef) {}

  check(): HealthCheckResult {
    return {
      status: 'ok',
      service: 'dcmp-backend',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
    };
  }

  /** Liveness — process up; does not check dependencies. */
  liveness(): HealthCheckResult {
    return this.check();
  }

  /** Readiness — PostgreSQL + Redis when configured as required. */
  async readiness(): Promise<ReadinessResult> {
    const checks: ReadinessResult['checks'] = {};
    let ready = true;

    try {
      const pg = this.moduleRef.get(ValidationPgPool, { strict: false });
      if (pg) {
        const r = await pg.pool.query('SELECT 1 AS ok');
        checks.postgres = { ok: r.rows[0]?.ok === 1 };
      } else {
        checks.postgres = { ok: true, detail: 'ValidationPgPool not loaded (memory auth mode)' };
      }
    } catch (e) {
      checks.postgres = { ok: false, detail: (e as Error).message };
      ready = false;
    }

    try {
      const redis = this.moduleRef.get<AuthRedisPort>(AUTH_REDIS, { strict: false });
      if (redis) {
        const ping = redis.ping ? await redis.ping() : redis.isAvailable();
        const ok = Boolean(ping) && redis.isAvailable();
        checks.redis = { ok, mode: redis.mode };
        if (process.env.AUTH_REDIS_REQUIRED === 'true' && !ok) ready = false;
        if (redis.mode === 'REAL' && !ok) ready = false;
      } else {
        checks.redis = { ok: false, detail: 'AUTH_REDIS not bound' };
        if (process.env.AUTH_REDIS_REQUIRED === 'true') ready = false;
      }
    } catch (e) {
      checks.redis = { ok: false, detail: (e as Error).message };
      if (process.env.AUTH_REDIS_REQUIRED === 'true') ready = false;
    }

    return { ready, checks, timestamp: new Date().toISOString() };
  }
}
