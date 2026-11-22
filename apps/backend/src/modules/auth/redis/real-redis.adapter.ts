import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { AuthRedisPort, RedisMode } from './redis.port';

/**
 * Real Redis adapter for DPoP JTI / nonce / retry-cache keys.
 * PostgreSQL remains durable authority for refresh rotation + idempotency.
 *
 * Fail-closed: when unavailable (or force-disabled for tests), operations throw REDIS_UNAVAILABLE.
 */
@Injectable()
export class RealRedisAdapter implements AuthRedisPort, OnModuleDestroy {
  readonly mode: RedisMode = 'REAL';
  private readonly logger = new Logger(RealRedisAdapter.name);
  private readonly client: Redis;
  private forceUnavailable = false;
  private connected = false;

  constructor() {
    const host = process.env.REDIS_HOST || '127.0.0.1';
    const port = parseInt(process.env.REDIS_PORT || '6379', 10);
    const password = process.env.REDIS_PASSWORD || undefined;
    const db = parseInt(process.env.REDIS_DB || '0', 10);
    const connectTimeout = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '3000', 10);
    const commandTimeout = parseInt(process.env.REDIS_COMMAND_TIMEOUT_MS || '2000', 10);

    this.client = new Redis({
      host,
      port,
      password,
      db,
      connectTimeout,
      commandTimeout,
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
      lazyConnect: false,
      retryStrategy: (times) => {
        if (times > 20) return null;
        return Math.min(times * 100, 2000);
      },
    });

    this.client.on('ready', () => {
      this.connected = true;
      this.logger.log(`Redis ready at ${host}:${port}/${db}`);
    });
    this.client.on('end', () => {
      this.connected = false;
    });
    this.client.on('error', (err) => {
      this.connected = false;
      this.logger.warn(`Redis error: ${err.message}`);
    });
  }

  isAvailable(): boolean {
    if (this.forceUnavailable) return false;
    return this.connected && this.client.status === 'ready';
  }

  setAvailable(available: boolean): void {
    this.forceUnavailable = !available;
  }

  private assertUp(): void {
    if (!this.isAvailable()) {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  async get(key: string): Promise<string | null> {
    this.assertUp();
    try {
      return await this.client.get(key);
    } catch {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.assertUp();
    try {
      await this.client.set(key, value, 'EX', ttlSeconds);
    } catch {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  async setNx(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    this.assertUp();
    try {
      const result = await this.client.set(key, value, 'EX', ttlSeconds, 'NX');
      return result === 'OK';
    } catch {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  async del(key: string): Promise<void> {
    this.assertUp();
    try {
      await this.client.del(key);
    } catch {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  /** Test helper: flush current DB only (never production). */
  async flushTestDb(): Promise<void> {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('flushTestDb forbidden in production');
    }
    await this.client.flushdb();
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.client.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }
}
