/**
 * Phase 2.1.16 — PostgreSQL AuthStore HTTP + concurrency integration.
 * Run ONLY via: npm run test:auth:postgres
 * (AUTH_STORE_DRIVER must be set before AuthModule import.)
 */
import assert from 'node:assert/strict';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { MemoryRedisAdapter } from '../redis/memory-redis.adapter';
import { AUTH_STORE } from '../persistence/auth-store.port';
import { PostgresAuthStore } from '../persistence/postgres-auth.store';
import { ValidationPgPool } from '../persistence/pg.pool';

assert.equal(
  process.env.AUTH_STORE_DRIVER,
  'postgres',
  'Run via npm run test:auth:postgres so AUTH_STORE_DRIVER is set before AuthModule loads',
);

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PASSWORD = 'Password123!';
const EMAIL = `pg-auth-${Date.now()}@example.com`;

describe('Phase 2.1.16 PostgreSQL AuthStore integration', () => {
  let app: INestApplication;
  let auth: AuthService;
  let store: PostgresAuthStore;
  let redis: MemoryRedisAdapter;
  let pg: ValidationPgPool;
  let baseUrl: string;
  let server: ReturnType<INestApplication['getHttpServer']>;

  before(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    const { ResponseTransformInterceptor } = await import(
      '../../../common/interceptors/response.interceptor'
    );
    const { GlobalHttpExceptionFilter } = await import(
      '../../../common/filters/http-exception.filter'
    );
    app.useGlobalInterceptors(new ResponseTransformInterceptor());
    app.useGlobalFilters(new GlobalHttpExceptionFilter());
    await app.init();

    const resolved = app.get(AUTH_STORE);
    assert.ok(
      resolved instanceof PostgresAuthStore,
      `Expected PostgresAuthStore, got ${resolved?.constructor?.name}`,
    );
    store = resolved;
    auth = app.get(AuthService);
    redis = app.get(MemoryRedisAdapter);
    pg = app.get(ValidationPgPool);

    const ver = await pg.pool.query(
      'SELECT version() AS version, current_database() AS db, inet_server_port() AS port',
    );
    assert.match(String(ver.rows[0].version), /PostgreSQL 16\.10/);
    assert.equal(ver.rows[0].db, 'dcmp_validation');
    assert.equal(Number(ver.rows[0].port), 55432);

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'PG Inspector',
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
  });

  after(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((e: Error | undefined) => (e ? reject(e) : resolve())),
    );
    await app.close();
  });

  async function http(
    method: string,
    path: string,
    opts: { body?: unknown; dpop?: string; headers?: Record<string, string> } = {},
  ) {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      ...(opts.headers || {}),
    };
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

  function tokensFrom(json: unknown): { refreshToken: string; accessToken: string } {
    const data = unwrapData<{
      tokens?: { refreshToken: string; accessToken: string };
      user?: unknown;
    }>(json);
    if (data.tokens) return data.tokens;
    throw new Error(`no tokens in ${JSON.stringify(json)}`);
  }

  async function loginPair(email = EMAIL, organizationId = ORG_A) {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu });
    const res = await http('POST', '/api/v1/auth/login', {
      dpop: minted.proof,
      body: { email, password: PASSWORD, organizationId },
    });
    assert.ok(res.status === 200 || res.status === 201, JSON.stringify(res.json));
    return {
      tokens: tokensFrom(res.json),
      nonce: res.nonce!,
      privateJwk: minted.privateJwk,
      jkt: minted.jkt,
    };
  }

  test('login creates durable session rows under dcmp_app RLS', async () => {
    const session = await loginPair();
    const st = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(st.status, 200);
    const data = unwrapData<{ active: boolean; sessionId: string; organizationId: string }>(
      st.json,
    );
    assert.equal(data.active, true);
    assert.equal(data.organizationId, ORG_A);
    const row = await store.getSession(ORG_A, data.sessionId);
    assert.ok(row?.isActive);
    assert.equal(row?.dpopJkt, session.jkt);
  });

  test('refresh rotation + same-proof retry recovers from PostgreSQL idempotency', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = crypto.randomUUID();
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      jti,
      privateJwk: session.privateJwk,
    });
    const r1 = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r1.status, 200, JSON.stringify(r1.json));
    const t1 = tokensFrom(r1.json).refreshToken;

    const r2 = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r2.status, 200, JSON.stringify(r2.json));
    assert.equal(tokensFrom(r2.json).refreshToken, t1);
  });

  test('divergent proof reuse revokes session in PostgreSQL', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const p1 = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const r1 = await http('POST', '/api/v1/auth/refresh', {
      dpop: p1.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r1.status, 200);

    const p2 = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: r1.nonce || session.nonce,
      privateJwk: session.privateJwk,
    });
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      dpop: p2.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r2.status, 401);
    assert.match(JSON.stringify(r2.json), /TOKEN_REUSE|SESSION_REVOKED|UNAUTHENTICATED/);
  });

  test('client organization header cannot authorize cross-tenant refresh', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
      headers: { [HTTP_HEADERS.ORGANIZATION_ID]: ORG_B },
    });
    assert.equal(res.status, 403);
  });

  test('forged organization header does not establish req.tenant authorization', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/me`;
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      headers: {
        [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}`,
        [HTTP_HEADERS.ORGANIZATION_ID]: ORG_B,
      },
    });
    assert.equal(me.status, 200);
    const payload = unwrapData<{ orgId: string }>(me.json);
    assert.equal(payload.orgId, ORG_A);
  });

  test('missing tenant GUC fails closed for direct dcmp_app SELECT', async () => {
    await pg.withAppClient(async (client) => {
      await client.query(`SELECT set_config('app.current_organization_id', '', true)`);
      const { rows } = await client.query(`SELECT count(*)::int AS n FROM public.users`);
      assert.equal(rows[0].n, 0);
    });
  });

  test('pooled connection does not leak prior organization GUC', async () => {
    await pg.withTenantTx(ORG_A, async (client) => {
      const { rows } = await client.query(
        `SELECT current_setting('app.current_organization_id', true) AS org`,
      );
      assert.equal(rows[0].org, ORG_A);
    });
    await pg.withAppClient(async (client) => {
      const { rows } = await client.query(
        `SELECT current_setting('app.current_organization_id', true) AS org`,
      );
      assert.ok(rows[0].org === '' || rows[0].org == null || rows[0].org !== ORG_A);
    });
  });

  test('cross-tenant session getSession returns null under wrong org GUC', async () => {
    const session = await loginPair();
    const st = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: session.tokens.refreshToken },
    });
    const data = unwrapData<{ sessionId: string }>(st.json);
    const foreign = await store.getSession(ORG_B, data.sessionId);
    assert.equal(foreign, null);
  });

  test('concurrent identical refresh — two independent HTTP clients', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = crypto.randomUUID();
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      jti,
      privateJwk: session.privateJwk,
    });
    const [a, b] = await Promise.all([
      http('POST', '/api/v1/auth/refresh', {
        dpop: proof,
        body: { refreshToken: session.tokens.refreshToken },
      }),
      http('POST', '/api/v1/auth/refresh', {
        dpop: proof,
        body: { refreshToken: session.tokens.refreshToken },
      }),
    ]);
    assert.equal(a.status, 200, JSON.stringify(a.json));
    assert.equal(b.status, 200, JSON.stringify(b.json));
    assert.equal(tokensFrom(a.json).refreshToken, tokensFrom(b.json).refreshToken);
  });

  test('logout blocks PostgreSQL idempotency recovery', async () => {
    const session = await loginPair();
    const htuRefresh = `${baseUrl}/api/v1/auth/refresh`;
    const first = await mintTestDpopProof({
      method: 'POST',
      htu: htuRefresh,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const rotated = await http('POST', '/api/v1/auth/refresh', {
      dpop: first.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(rotated.status, 200);
    const newRefresh = tokensFrom(rotated.json).refreshToken;

    const logoutProof = await mintTestDpopProof({
      method: 'POST',
      htu: `${baseUrl}/api/v1/auth/logout`,
      privateJwk: session.privateJwk,
    });
    const logout = await http('POST', '/api/v1/auth/logout', {
      dpop: logoutProof.proof,
      body: { refreshToken: newRefresh },
    });
    assert.equal(logout.status, 200);

    const retry = await http('POST', '/api/v1/auth/refresh', {
      dpop: first.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(retry.status, 401);
  });

  test('session revoke via access token blocks recovery', async () => {
    const session = await loginPair();
    const htuRefresh = `${baseUrl}/api/v1/auth/refresh`;
    const first = await mintTestDpopProof({
      method: 'POST',
      htu: htuRefresh,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const rotated = await http('POST', '/api/v1/auth/refresh', {
      dpop: first.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(rotated.status, 200);
    const access = tokensFrom(rotated.json).accessToken;
    const st = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: tokensFrom(rotated.json).refreshToken },
    });
    const { sessionId } = unwrapData<{ sessionId: string }>(st.json);

    const revokeHtu = `${baseUrl}/api/v1/auth/sessions/revoke`;
    const forgedProof = await mintTestDpopProof({
      method: 'POST',
      htu: revokeHtu,
      accessToken: access,
      privateJwk: session.privateJwk,
    });
    const forged = await http('POST', '/api/v1/auth/sessions/revoke', {
      dpop: forgedProof.proof,
      body: { organizationId: ORG_B, sessionId },
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${access}` },
    });
    assert.equal(forged.status, 403);

    const okProof = await mintTestDpopProof({
      method: 'POST',
      htu: revokeHtu,
      accessToken: access,
      privateJwk: session.privateJwk,
    });
    const ok = await http('POST', '/api/v1/auth/sessions/revoke', {
      dpop: okProof.proof,
      body: { organizationId: ORG_A, sessionId },
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${access}` },
    });
    assert.equal(ok.status, 200);

    const retry = await http('POST', '/api/v1/auth/refresh', {
      dpop: first.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(retry.status, 401);
  });

  test('Redis unavailable fails closed for new proof with Postgres store', async () => {
    const session = await loginPair();
    redis.setAvailable(false);
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    redis.setAvailable(true);
    assert.equal(res.status, 503);
    assert.match(JSON.stringify(res.json), /DPOP_REPLAY_STORE_UNAVAILABLE/);
  });

  test('invalid DPoP does not revoke PostgreSQL session', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const bad = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof.slice(0, -6) + 'abcdef',
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(bad.status, 401);
    const st = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: session.tokens.refreshToken },
    });
    const data = unwrapData<{ active: boolean }>(st.json);
    assert.equal(data.active, true);
  });

  test('two independent pool connections see isolated tenant GUC', async () => {
    const results = await Promise.all([
      pg.withTenantTx(ORG_A, async (client) => {
        const { rows } = await client.query(
          `SELECT current_setting('app.current_organization_id', true) AS org`,
        );
        await new Promise((r) => setTimeout(r, 40));
        return rows[0].org as string;
      }),
      pg.withTenantTx(ORG_B, async (client) => {
        const { rows } = await client.query(
          `SELECT current_setting('app.current_organization_id', true) AS org`,
        );
        await new Promise((r) => setTimeout(r, 40));
        return rows[0].org as string;
      }),
    ]);
    assert.deepEqual(results.sort(), [ORG_A, ORG_B].sort());
  });
});
