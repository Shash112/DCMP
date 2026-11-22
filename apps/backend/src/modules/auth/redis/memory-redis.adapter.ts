import { Injectable } from '@nestjs/common';
import { AuthRedisPort, RedisMode } from './redis.port';

interface Entry {
  value: string;
  expiresAt: number;
}

@Injectable()
export class MemoryRedisAdapter implements AuthRedisPort {
  readonly mode: RedisMode = 'MEMORY';
  private store = new Map<string, Entry>();
  private available = true;

  isAvailable(): boolean {
    return this.available;
  }

  setAvailable(available: boolean): void {
    this.available = available;
  }

  private assertUp(): void {
    if (!this.available) {
      throw new Error('REDIS_UNAVAILABLE');
    }
  }

  private purge(key: string): void {
    const e = this.store.get(key);
    if (e && e.expiresAt <= Date.now()) this.store.delete(key);
  }

  async get(key: string): Promise<string | null> {
    this.assertUp();
    this.purge(key);
    return this.store.get(key)?.value ?? null;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.assertUp();
    this.store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async setNx(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    this.assertUp();
    this.purge(key);
    if (this.store.has(key)) return false;
    this.store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    return true;
  }

  async del(key: string): Promise<void> {
    this.assertUp();
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}
