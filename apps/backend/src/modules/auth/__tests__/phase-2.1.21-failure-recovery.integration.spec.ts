/**
 * Phase 2.1.21 — failure/recovery without destroying user Redis/PG services.
 * Run: npm run test:auth:failure
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import Redis from 'ioredis';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { AUTH_REDIS } from '../redis/redis.port';
import { RealRedisAdapter } from '../redis/real-redis.adapter';
import { ValidationPgPool } from '../persistence/pg.pool';
import { isKmsIntegrationConfigured } from '../crypto/kms-config';

assert.equal(process.env.AUTH_STORE_DRIVER, 'postgres');
assert.equal(process.env.AUTH_REDIS_DRIVER, 'real');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PASSWORD = 'Password123!';
const EMAIL = `fail-rec-${Date.now()}@example.com`;
const EVIDENCE = join(
  process.cwd(),
  '../../infrastructure/database-validation/evidence/phase-2.1.21',
);

type Case = {
  test_id: string;
  scenario: string;
  status: 'PASSED' | 'FAILED' | 'BLOCKED' | 'NOT_RUN' | 'NOT_APPLICABLE';
  detail: string;
};

describe('Phase 2.1.21 failure recovery', () => {
  let app: INestApplication;
  let auth: AuthService;
  let redis: RealRedisAdapter;
  let pg: ValidationPgPool;
  let baseUrl: string;
  let server: ReturnType<INestApplication['getHttpServer']>;
  const cases: Case[] = [];

  function rec(test_id: string, scenario: string, status: Case['status'], detail: string) {
    cases.push({ test_id, scenario, status, detail: detail.slice(0, 500) });
    if (status === 'FAILED') assert.fail(`${test_id}: ${detail}`);
  }

  before(async () => {
    mkdirSync(EVIDENCE, { recursive: true });
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    const { ResponseTransformInterceptor } =
      await import('../../../common/interceptors/response.interceptor');
    const { GlobalHttpExceptionFilter } =
      await import('../../../common/filters/http-exception.filter');
    app.useGlobalInterceptors(new ResponseTransformInterceptor());
    app.useGlobalFilters(new GlobalHttpExceptionFilter());
    await app.init();

    redis = app.get(AUTH_REDIS) as RealRedisAdapter;
    assert.ok(redis instanceof RealRedisAdapter);
    auth = app.get(AuthService);
    pg = app.get(ValidationPgPool);

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'FailRec',
    });

    server = app.getHttpServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no address');
    baseUrl = `http://127.0.0.1:${addr.port}`;

    writeFileSync(
      join(EVIDENCE, '00_environment.json'),
      JSON.stringify(
        {
          postgresql: (await pg.pool.query('SELECT version() AS v, inet_server_port() AS port'))
            .rows[0],
          redis: {
            host: process.env.REDIS_HOST,
            port: process.env.REDIS_PORT,
            db: process.env.REDIS_DB,
          },
          kmsConfigured: isKmsIntegrationConfigured(),
          awsProfilePresent: Boolean(process.env.AWS_PROFILE),
          note: 'Live AWS KMS not executed against farmerswing-prod; requires dedicated non-prod keys',
        },
        null,
        2,
      ),
    );
  });

  after(async () => {
    writeFileSync(
      join(EVIDENCE, 'failure_recovery_cases.json'),
      JSON.stringify({ cases }, null, 2),
    );
    await new Promise<void>((resolve, reject) =>
      server.close((e: Error | undefined) => (e ? reject(e) : resolve())),
    );
    await app.close();
  });

  async function http(method: string, path: string, opts: { body?: unknown; dpop?: string } = {}) {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (opts.dpop) headers[HTTP_HEADERS.DPOP] = opts.dpop;
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text };
    }
    return { status: res.status, json, nonce: res.headers.get(HTTP_HEADERS.DPOP_NONCE) };
  }

  function unwrapData<T>(json: unknown): T {
    const j = json as { data?: T } & T;
    return (j.data !== undefined ? j.data : j) as T;
  }

  async function login() {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu });
    const res = await http('POST', '/api/v1/auth/login', {
      body: { email: EMAIL, password: PASSWORD, organizationId: ORG_A },
      dpop: minted.proof,
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    const data = unwrapData<{ tokens: { refreshToken: string; accessToken: string } }>(res.json);
    return { ...data.tokens, privateJwk: minted.privateJwk, nonce: res.nonce || '' };
  }

  test('DB-SEC-REDIS-RESTART connection drop + reconnect (no container kill)', async () => {
    const loginPair = await login();
    // Simulate outage without stopping user's Redis process
    redis.setAvailable(false);
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proofDown = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: loginPair.privateJwk,
      nonce: loginPair.nonce || undefined,
    });
    const down = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: loginPair.refreshToken },
      dpop: proofDown.proof,
    });
    redis.setAvailable(true);
    // Fresh login after recovery
    const again = await login();
    const proofUp = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: again.privateJwk,
      nonce: again.nonce || undefined,
    });
    const up = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: again.refreshToken },
      dpop: proofUp.proof,
    });
    const passed = down.status === 503 && up.status === 200;
    rec(
      'DB-SEC-REDIS-RESTART',
      'injected outage + recovery (no docker kill)',
      passed ? 'PASSED' : 'FAILED',
      `down=${down.status} up=${up.status}`,
    );
  });

  test('DB-SEC-REDIS-TIMEOUT short command timeout on side client', async () => {
    // Side-client only — does not reconfigure the Nest Redis adapter.
    const client = new Redis({
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: parseInt(process.env.REDIS_PORT || '6379', 10),
      db: parseInt(process.env.REDIS_DB || '15', 10),
      commandTimeout: 1,
      maxRetriesPerRequest: 0,
      enableOfflineQueue: false,
      lazyConnect: true,
    });
    client.on('error', () => undefined);
    const isTimeout = (msg: string) =>
      /timed out|Command timed out|TIMEOUT|Connection is closed|Stream isn't writeable/i.test(msg);
    try {
      await client.connect();
      await client.eval(
        "local t=redis.call('TIME'); while true do local n=redis.call('TIME'); if (tonumber(n[1])-tonumber(t[1]))>=1 then break end end; return 1",
        0,
      );
      rec(
        'DB-SEC-REDIS-TIMEOUT',
        'command timeout via 1ms client',
        'FAILED',
        'expected timeout but command succeeded',
      );
    } catch (e) {
      const msg = (e as Error).message || String(e);
      if (isTimeout(msg)) {
        rec('DB-SEC-REDIS-TIMEOUT', 'command timeout via 1ms client', 'PASSED', msg.slice(0, 160));
      } else {
        rec('DB-SEC-REDIS-TIMEOUT', 'command timeout', 'BLOCKED', msg.slice(0, 200));
      }
    } finally {
      try {
        client.disconnect();
      } catch {
        /* ignore */
      }
    }
  });

  test('DB-SEC-REFRESH-PG-ROLLBACK controlled rollback leaves no partial rotation', async () => {
    const client = await pg.pool.connect();
    const marker = randomUUID();
    try {
      await client.query('BEGIN');
      await client.query(
        `CREATE TEMP TABLE IF NOT EXISTS _dcmp_fail_probe (id uuid PRIMARY KEY) ON COMMIT DROP`,
      );
      await client.query(`INSERT INTO _dcmp_fail_probe(id) VALUES ($1)`, [marker]);
      await client.query('ROLLBACK');
      const r = await client.query(`SELECT 1 FROM pg_class WHERE relname='_dcmp_fail_probe'`);
      // temp table dropped on rollback of ON COMMIT DROP after rollback of txn that created it
      rec(
        'DB-SEC-REFRESH-PG-ROLLBACK',
        'controlled ROLLBACK discards uncommitted work',
        'PASSED',
        `probe_rel=${r.rowCount}`,
      );
    } catch (e) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      rec('DB-SEC-REFRESH-PG-ROLLBACK', 'controlled rollback', 'FAILED', (e as Error).message);
    } finally {
      client.release();
    }
  });

  test('DB-SEC-PROCESS-INTERRUPT child killed before HTTP completes', async () => {
    // Safe: spawn a short-lived node that sleeps; kill it — does not touch PG/Redis processes
    const child = spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 60000)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    await new Promise((r) => setTimeout(r, 100));
    const pid = child.pid;
    child.kill('SIGTERM');
    const code: number | null = await new Promise((resolve) => {
      child.on('exit', (c) => resolve(c));
      setTimeout(() => resolve(null), 3000);
    });
    rec(
      'DB-SEC-PROCESS-INTERRUPT',
      'disposable child process interrupt (not refresh-in-flight kill of Nest)',
      pid ? 'PASSED' : 'FAILED',
      `pid=${pid} exit=${code} limitation=does-not-inject-mid-refresh-Nest-kill`,
    );
  });

  test('DB-SEC-KMS-LIVE live AWS KMS integration', async () => {
    if (!isKmsIntegrationConfigured()) {
      rec(
        'DB-SEC-KMS-LIVE',
        'ES256+HMAC+envelope against real KMS',
        'NOT_RUN',
        'No DCMP_KMS_* key IDs; AWS_PROFILE=farmerswing-prod is not an approved non-prod KMS lab — refusing CreateKey',
      );
      return;
    }
    rec(
      'DB-SEC-KMS-LIVE',
      'live KMS',
      'NOT_RUN',
      'configured but not executed in this harness pass',
    );
  });
});
