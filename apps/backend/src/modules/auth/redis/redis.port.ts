export const AUTH_REDIS = Symbol('AUTH_REDIS');

export type RedisMode = 'MEMORY' | 'SIMULATED_FAILURE' | 'REAL';

/**
 * Minimal Redis port for auth cache / JTI / nonce.
 * REAL mode uses disposable/local Redis; MEMORY is for unit/offline suites only.
 * Production / AUTH_REDIS_REQUIRED must not silently fall back to MEMORY.
 */
export interface AuthRedisPort {
  readonly mode: RedisMode;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** SET key value EX ttl NX — returns true if set, false if exists */
  setNx(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  del(key: string): Promise<void>;
  /** Force outage for failure-injection tests */
  setAvailable?(available: boolean): void;
  isAvailable(): boolean;
  ping?(): Promise<boolean>;
}

export function resolveAuthRedisDriver(): 'memory' | 'real' {
  const raw = (process.env.AUTH_REDIS_DRIVER || '').toLowerCase();
  if (raw === 'real' || raw === 'redis') return 'real';
  if (raw === 'memory') return 'memory';

  // Default: real when REDIS_HOST set or AUTH_REDIS_REQUIRED; else memory for legacy suites
  if (process.env.AUTH_REDIS_REQUIRED === 'true') return 'real';
  if (process.env.REDIS_HOST) return 'real';
  return 'memory';
}

export function assertRedisDriverAllowed(driver: 'memory' | 'real'): void {
  const required =
    process.env.AUTH_REDIS_REQUIRED === 'true' || process.env.NODE_ENV === 'production';
  if (required && driver === 'memory') {
    throw new Error(
      'Refusing MemoryRedisAdapter: AUTH_REDIS_REQUIRED/production forbids insecure memory fallback',
    );
  }
}
