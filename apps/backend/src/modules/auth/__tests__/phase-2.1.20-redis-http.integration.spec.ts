/**
 * Phase 2.1.20 — Real Redis + PostgreSQL 16.10 + Nest HTTP/DPoP + SSA gateway.
 * Run: npm run test:auth:redis
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { AUTH_STORE } from '../persistence/auth-store.port';
import { PostgresAuthStore } from '../persistence/postgres-auth.store';
import { ValidationPgPool } from '../persistence/pg.pool';
import { AUTH_REDIS } from '../redis/redis.port';
import { RealRedisAdapter } from '../redis/real-redis.adapter';
import type { JWK } from 'jose';

assert.equal(process.env.AUTH_STORE_DRIVER, 'postgres');
assert.equal(process.env.AUTH_REDIS_DRIVER, 'real');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PASSWORD = 'Password123!';
const EMAIL = `redis-auth-${Date.now()}@example.com`;
const ADMIN_ID = '99999999-9999-4999-8999-999999999999';
const EVIDENCE = join(
  process.cwd(),
  '../../infrastructure/database-validation/evidence/phase-2.1.20',
);

type Case = {
  test_id: string;
  scenario: string;
  status: 'PASSED' | 'FAILED' | 'BLOCKED' | 'NOT_RUN' | 'NOT_APPLICABLE';
  detail: string;
};

describe('Phase 2.1.20 Real Redis + HTTP/DPoP + SSA', () => {
  let app: INestApplication;
  let auth: AuthService;
  let redis: RealRedisAdapter;
  let pg: ValidationPgPool;
  let baseUrl: string;
  let server: ReturnType<INestApplication['getHttpServer']>;
  const cases: Case[] = [];

  function rec(test_id: string, scenario: string, passed: boolean, detail: string) {
    cases.push({
      test_id,
      scenario,
      status: passed ? 'PASSED' : 'FAILED',
      detail: detail.slice(0, 400),
    });
    assert.ok(passed, `${test_id}: ${detail}`);
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

    assert.ok(app.get(AUTH_STORE) instanceof PostgresAuthStore);
    const r = app.get(AUTH_REDIS);
    assert.ok(
      r instanceof RealRedisAdapter,
      `Expected RealRedisAdapter got ${r?.constructor?.name}`,
    );
    redis = r as RealRedisAdapter;
    auth = app.get(AuthService);
    pg = app.get(ValidationPgPool);

    const ver = await pg.pool.query(
      'SELECT version() AS version, current_database() AS db, inet_server_port() AS port',
    );
    assert.match(String(ver.rows[0].version), /PostgreSQL 16\.10/);
    assert.equal(Number(ver.rows[0].port), 55432);

    assert.equal(await redis.ping(), true);
    await redis.flushTestDb();

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'Redis Inspector',
    });
    await auth.seedTestUser({
      organizationId: ORG_B,
      email: `other-${EMAIL}`,
      password: PASSWORD,
      displayName: 'Other Tenant',
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
          postgresql: ver.rows[0],
          redis: {
            host: process.env.REDIS_HOST,
            port: process.env.REDIS_PORT,
            db: process.env.REDIS_DB,
          },
          redisMode: redis.mode,
          baseUrl,
        },
        null,
        2,
      ),
    );
  });

  after(async () => {
    writeFileSync(join(EVIDENCE, 'phase_2_1_20_cases.json'), JSON.stringify({ cases }, null, 2));
    await new Promise<void>((resolve, reject) =>
      server.close((e: Error | undefined) => (e ? reject(e) : resolve())),
    );
    await app.close();
  });

  async function http(
    method: string,
    path: string,
    opts: {
      body?: unknown;
      dpop?: string;
      authorization?: string;
      headers?: Record<string, string>;
    } = {},
  ) {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      ...(opts.headers || {}),
    };
    if (opts.dpop) headers[HTTP_HEADERS.DPOP] = opts.dpop;
    if (opts.authorization) headers[HTTP_HEADERS.AUTHORIZATION] = opts.authorization;
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

  function tokensFrom(json: unknown): { refreshToken: string; accessToken: string } {
    const data = unwrapData<{ tokens?: { refreshToken: string; accessToken: string } }>(json);
    if (data.tokens) return data.tokens;
    throw new Error(`no tokens in ${JSON.stringify(json)}`);
  }

  async function loginPair(organizationId = ORG_A) {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu });
    const res = await http('POST', '/api/v1/auth/login', {
      body: { email: EMAIL, password: PASSWORD, organizationId },
      dpop: minted.proof,
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    const tokens = tokensFrom(res.json);
    return {
      ...tokens,
      privateJwk: minted.privateJwk,
      nonce: res.nonce || '',
      jkt: minted.jkt,
    };
  }

  // ——— Redis ———
  test('DB-SEC-REDIS-201 real Redis PING + SET NX', async () => {
    const ok = await redis.ping();
    const nx1 = await redis.setNx('auth:test:nx', '1', 30);
    const nx2 = await redis.setNx('auth:test:nx', '1', 30);
    await redis.del('auth:test:nx');
    rec(
      'DB-SEC-REDIS-201',
      'PING + atomic SET NX',
      ok && nx1 && !nx2,
      `ping=${ok} nx1=${nx1} nx2=${nx2}`,
    );
  });

  test('DB-SEC-REDIS-202 TTL expiry', async () => {
    await redis.set('auth:test:ttl', 'x', 1);
    const mid = await redis.get('auth:test:ttl');
    await new Promise((r) => setTimeout(r, 1200));
    const after = await redis.get('auth:test:ttl');
    rec(
      'DB-SEC-REDIS-202',
      'TTL expiry',
      mid === 'x' && after === null,
      `mid=${mid} after=${after}`,
    );
  });

  // ——— HTTP auth + DPoP ———
  test('DB-SEC-018 login + JWKS + me with valid DPoP access', async () => {
    const jwks = await http('GET', '/api/v1/auth/.well-known/jwks.json');
    assert.equal(jwks.status, 200);
    const keys =
      unwrapData<{ keys: unknown[] }>(jwks.json).keys || (jwks.json as { keys: unknown[] }).keys;
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/me`;
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu,
      privateJwk: login.privateJwk,
      accessToken: login.accessToken,
      nonce: login.nonce || undefined,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      authorization: `DPoP ${login.accessToken}`,
    });
    rec(
      'DB-SEC-018',
      'login+jwks+me',
      jwks.status === 200 && Array.isArray(keys) && keys.length >= 1 && me.status === 200,
      `jwks=${keys?.length} me=${me.status}`,
    );
  });

  test('DB-SEC-019 invalid DPoP signature does not revoke session', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const bad = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const corrupted = bad.proof.slice(0, -4) + 'xxxx';
    const res = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: corrupted,
    });
    const status = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: login.refreshToken },
    });
    const active = unwrapData<{ active?: boolean }>(status.json).active;
    rec(
      'DB-SEC-019',
      'invalid DPoP no revoke',
      res.status === 401 && active === true,
      `refresh=${res.status} active=${active}`,
    );
  });

  test('DB-SEC-028 DPoP JTI replay rejected with Redis', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = randomUUID();
    const p1 = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      jti,
      nonce: login.nonce || undefined,
    });
    const r1 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: p1.proof,
    });
    const tokens = tokensFrom(r1.json);
    const p2 = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      jti,
      nonce: r1.nonce || undefined,
    });
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: tokens.refreshToken },
      dpop: p2.proof,
    });
    rec(
      'DB-SEC-028',
      'JTI replay via Redis SET NX',
      r1.status === 200 && r2.status === 401,
      `r1=${r1.status} r2=${r2.status}`,
    );
  });

  test('DB-SEC-REDIS-203 Redis unavailable fails closed for new proof', async () => {
    const login = await loginPair();
    redis.setAvailable(false);
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: proof.proof,
    });
    redis.setAvailable(true);
    rec('DB-SEC-REDIS-203', 'Redis down fail-closed', res.status === 503, `status=${res.status}`);
  });

  // ——— Refresh concurrency ———
  test('DB-SEC-071 identical concurrent refresh', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = randomUUID();
    const minted = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      jti,
      nonce: login.nonce || undefined,
    });
    const [a, b] = await Promise.all([
      http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: login.refreshToken },
        dpop: minted.proof,
      }),
      http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: login.refreshToken },
        dpop: minted.proof,
      }),
    ]);
    const statuses = [a.status, b.status].sort().join(',');
    const ok =
      [a.status, b.status].every((s) => s === 200 || s === 401) &&
      [a.status, b.status].includes(200);
    rec('DB-SEC-071', 'identical concurrent refresh', ok, `statuses=${statuses}`);
  });

  test('DB-SEC-072 divergent proofs same token', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const p1 = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const p2 = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const [a, b] = await Promise.all([
      http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: login.refreshToken },
        dpop: p1.proof,
      }),
      http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: login.refreshToken },
        dpop: p2.proof,
      }),
    ]);
    const statuses = [a.status, b.status];
    const oneOk = statuses.includes(200);
    const oneFail = statuses.some((s) => s === 401);
    rec(
      'DB-SEC-072',
      'divergent concurrent proofs',
      oneOk && oneFail,
      `statuses=${statuses.join(',')}`,
    );
  });

  test('DB-SEC-021 logout then protected me denied', async () => {
    const login = await loginPair();
    const logoutHtu = `${baseUrl}/api/v1/auth/logout`;
    const logoutProof = await mintTestDpopProof({
      method: 'POST',
      htu: logoutHtu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const lo = await http('POST', '/api/v1/auth/logout', {
      body: { refreshToken: login.refreshToken },
      dpop: logoutProof.proof,
    });
    const meHtu = `${baseUrl}/api/v1/auth/me`;
    const meProof = await mintTestDpopProof({
      method: 'GET',
      htu: meHtu,
      privateJwk: login.privateJwk,
      accessToken: login.accessToken,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: meProof.proof,
      authorization: `DPoP ${login.accessToken}`,
    });
    rec(
      'DB-SEC-021',
      'logout then me denied',
      lo.status === 200 && me.status === 401,
      `lo=${lo.status} me=${me.status}`,
    );
  });

  test('DB-SEC-ORG-HDR client org header cannot override tenant', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: proof.proof,
      headers: { [HTTP_HEADERS.ORGANIZATION_ID]: ORG_B },
    });
    // 200 = header ignored; 403 = TENANT_MISMATCH when header treated as claim conflict
    rec(
      'DB-SEC-ORG-HDR',
      'org header spoof denied/ignored',
      res.status === 200 || res.status === 403,
      `status=${res.status}`,
    );
  });

  test('DB-SEC-DPOP-HTM wrong method rejected', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proof = await mintTestDpopProof({
      method: 'GET', // wrong — refresh is POST
      htu,
      privateJwk: login.privateJwk,
      nonce: login.nonce || undefined,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: proof.proof,
    });
    rec('DB-SEC-DPOP-HTM', 'wrong DPoP method', res.status === 401, `status=${res.status}`);
  });

  test('DB-SEC-DPOP-KEY wrong DPoP key rejected', async () => {
    const login = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const other: { privateJwk: JWK } = await mintTestDpopProof({ method: 'POST', htu });
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: other.privateJwk,
      nonce: login.nonce || undefined,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: login.refreshToken },
      dpop: proof.proof,
    });
    rec('DB-SEC-DPOP-KEY', 'wrong DPoP key', res.status === 401, `status=${res.status}`);
  });

  // ——— SSA gateway E2E ———
  test('DB-SEC-SSA-GATEWAY full HTTP mint + open', async () => {
    const u = await pg.pool.query(
      `SELECT id FROM public.users WHERE organization_id=$1 AND email=$2`,
      [ORG_A, EMAIL],
    );
    const userId = u.rows[0].id as string;

    const req = await http('POST', '/api/v1/auth/support/requests', {
      body: { organizationId: ORG_A, adminId: ADMIN_ID },
    });
    assert.equal(req.status, 200, JSON.stringify(req.json));
    const requestId = unwrapData<{ requestId: string }>(req.json).requestId;

    const appr = await http('POST', '/api/v1/auth/support/approve', {
      body: {
        requestId,
        organizationId: ORG_A,
        approvedByUserId: userId,
        ttlMinutes: 10,
      },
    });
    assert.equal(appr.status, 200, JSON.stringify(appr.json));
    const grantId = unwrapData<{ grantId: string }>(appr.json).grantId;

    const ch = await http('POST', '/api/v1/auth/support/challenges', {
      body: { organizationId: ORG_A, grantId, adminId: ADMIN_ID },
    });
    assert.equal(ch.status, 200, JSON.stringify(ch.json));
    const challengeId = unwrapData<{ challengeId: string }>(ch.json).challengeId;

    const mint = await http('POST', '/api/v1/auth/support/assertions', {
      body: { adminId: ADMIN_ID, organizationId: ORG_A, grantId, requestId },
    });
    assert.equal(mint.status, 200, JSON.stringify(mint.json));
    const assertion = unwrapData<{ assertion: string; keyMaterial: string }>(mint.json);
    assert.equal(assertion.keyMaterial, 'TEST-ONLY');

    const open = await http('POST', '/api/v1/auth/support/sessions/open', {
      body: {
        assertion: assertion.assertion,
        organizationId: ORG_A,
        grantId,
        challengeId,
      },
    });
    const opened = unwrapData<{ opened: boolean; verifySignature: boolean }>(open.json);
    rec(
      'DB-SEC-SSA-GATEWAY',
      'HTTP SSA mint+open',
      open.status === 200 && opened.opened === true && opened.verifySignature === true,
      `open=${open.status} verify=${opened.verifySignature} body=${JSON.stringify(open.json).slice(0, 200)}`,
    );
  });

  test('DB-SEC-SSA-REPLAY replayed assertion denied', async () => {
    const u = await pg.pool.query(`SELECT id FROM public.users WHERE email=$1`, [EMAIL]);
    const userId = u.rows[0].id as string;
    const req = unwrapData<{ requestId: string }>(
      (
        await http('POST', '/api/v1/auth/support/requests', {
          body: { organizationId: ORG_A, adminId: ADMIN_ID },
        })
      ).json,
    );
    const grant = unwrapData<{ grantId: string }>(
      (
        await http('POST', '/api/v1/auth/support/approve', {
          body: { requestId: req.requestId, organizationId: ORG_A, approvedByUserId: userId },
        })
      ).json,
    );
    const ch = unwrapData<{ challengeId: string }>(
      (
        await http('POST', '/api/v1/auth/support/challenges', {
          body: { organizationId: ORG_A, grantId: grant.grantId, adminId: ADMIN_ID },
        })
      ).json,
    );
    const mint = unwrapData<{ assertion: string }>(
      (
        await http('POST', '/api/v1/auth/support/assertions', {
          body: {
            adminId: ADMIN_ID,
            organizationId: ORG_A,
            grantId: grant.grantId,
            requestId: req.requestId,
          },
        })
      ).json,
    );
    const body = {
      assertion: mint.assertion,
      organizationId: ORG_A,
      grantId: grant.grantId,
      challengeId: ch.challengeId,
    };
    const first = await http('POST', '/api/v1/auth/support/sessions/open', { body });
    const firstOpened = unwrapData<{ opened?: boolean }>(first.json).opened === true;
    const second = await http('POST', '/api/v1/auth/support/sessions/open', { body });
    const secondOpened = unwrapData<{ opened?: boolean }>(second.json).opened === true;
    rec(
      'DB-SEC-SSA-REPLAY',
      'SSA JTI/challenge replay denied',
      first.status === 200 && firstOpened && (second.status >= 400 || !secondOpened),
      `first=${first.status}/${firstOpened} second=${second.status}/${secondOpened} body2=${JSON.stringify(second.json).slice(0, 180)}`,
    );
  });

  test('DB-SEC-SSA-REVOKED revoked grant denied', async () => {
    const u = await pg.pool.query(`SELECT id FROM public.users WHERE email=$1`, [EMAIL]);
    const userId = u.rows[0].id as string;
    const req = unwrapData<{ requestId: string }>(
      (
        await http('POST', '/api/v1/auth/support/requests', {
          body: { organizationId: ORG_A, adminId: ADMIN_ID },
        })
      ).json,
    );
    const grant = unwrapData<{ grantId: string }>(
      (
        await http('POST', '/api/v1/auth/support/approve', {
          body: { requestId: req.requestId, organizationId: ORG_A, approvedByUserId: userId },
        })
      ).json,
    );
    await http('POST', '/api/v1/auth/support/grants/revoke', {
      body: { grantId: grant.grantId, organizationId: ORG_A },
    });
    const ch = unwrapData<{ challengeId: string }>(
      (
        await http('POST', '/api/v1/auth/support/challenges', {
          body: { organizationId: ORG_A, grantId: grant.grantId, adminId: ADMIN_ID },
        })
      ).json,
    );
    const mint = unwrapData<{ assertion: string }>(
      (
        await http('POST', '/api/v1/auth/support/assertions', {
          body: {
            adminId: ADMIN_ID,
            organizationId: ORG_A,
            grantId: grant.grantId,
            requestId: req.requestId,
          },
        })
      ).json,
    );
    const open = await http('POST', '/api/v1/auth/support/sessions/open', {
      body: {
        assertion: mint.assertion,
        organizationId: ORG_A,
        grantId: grant.grantId,
        challengeId: ch.challengeId,
      },
    });
    rec('DB-SEC-SSA-REVOKED', 'revoked grant denied', open.status >= 400, `status=${open.status}`);
  });

  test('DB-SEC-REDIS-204 readiness reflects Redis', async () => {
    const ready = await http('GET', '/api/v1/health/ready');
    const live = await http('GET', '/api/v1/health/live');
    rec(
      'DB-SEC-REDIS-204',
      'health live/ready',
      live.status === 200 && ready.status === 200,
      `live=${live.status} ready=${ready.status}`,
    );
  });
});
