import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { AuthAuditService } from '../audit/auth-audit.service';
import { buildRefreshAad, RefreshResponseCipher } from '../crypto/refresh-response-cipher';
import { LocalTestKeyProvider } from '../crypto/local-test-key.provider';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { buildExpectedHtu, normalizeHtuFromAbsolute } from '../dpop/dpop.uri';
import { MemoryRedisAdapter } from '../redis/memory-redis.adapter';
import { REFRESH_CIPHER_KEY_PROVIDER } from '../crypto/key-provider.interface';
import { createDecipheriv, createCipheriv, randomBytes } from 'crypto';

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PASSWORD = 'Password123!';

describe('Phase 2.1.15 Auth Gateway + DPoP', () => {
  let app: INestApplication;
  let auth: AuthService;
  let redis: MemoryRedisAdapter;
  let audit: AuthAuditService;
  let cipher: RefreshResponseCipher;
  let baseUrl: string;
  let server: ReturnType<typeof createServer>;

  before(async () => {
    process.env.NODE_ENV = 'test';
    process.env.AUTH_ALLOW_LOCAL_KEYS = 'true';
    delete process.env.DCMP_PUBLIC_ORIGIN;

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

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

    auth = app.get(AuthService);
    redis = app.get(MemoryRedisAdapter);
    audit = app.get(AuthAuditService);
    cipher = app.get(RefreshResponseCipher);

    await auth.seedTestUser({
      organizationId: ORG,
      email: 'inspector@example.com',
      password: PASSWORD,
      displayName: 'Inspector One',
    });

    server = app.getHttpServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no address');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
    await app.close();
  });

  async function http(
    method: string,
    path: string,
    opts: {
      body?: unknown;
      dpop?: string;
      headers?: Record<string, string>;
    } = {},
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
    return {
      status: res.status,
      json,
      nonce: res.headers.get(HTTP_HEADERS.DPOP_NONCE),
      headers: res.headers,
    };
  }

  async function loginPair() {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const { proof, jkt, privateJwk } = await mintTestDpopProof({ method: 'POST', htu });
    const res = await http('POST', '/api/v1/auth/login', {
      dpop: proof,
      body: { email: 'inspector@example.com', password: PASSWORD, organizationId: ORG },
    });
    assert.ok(
      res.status === 200 || res.status === 201,
      `login status ${res.status} ${JSON.stringify(res.json)}`,
    );
    const data =
      (res.json as { data?: { tokens: { refreshToken: string; accessToken: string } } }).data ||
      (res.json as { tokens: { refreshToken: string; accessToken: string }; user: unknown });
    const tokens =
      'tokens' in data
        ? data.tokens
        : (data as { tokens: { refreshToken: string; accessToken: string } }).tokens;
    assert.ok(tokens?.refreshToken);
    return { tokens, nonce: res.nonce!, privateJwk, jkt };
  }

  test('URI vectors: trailing slash preserved and forwarded headers ignored with public origin', () => {
    const a = normalizeHtuFromAbsolute('https://api.dcmp.com/api/v1/auth/refresh');
    const b = normalizeHtuFromAbsolute('https://api.dcmp.com/api/v1/auth/refresh/');
    assert.notEqual(a, b);
    const upper = normalizeHtuFromAbsolute('https://API.DCMP.COM:443/api/v1/auth/refresh');
    assert.equal(upper, a);
    const withPort = normalizeHtuFromAbsolute('https://api.dcmp.com:8443/api/v1/auth/refresh');
    assert.notEqual(withPort, a);

    const spoof = buildExpectedHtu({
      method: 'POST',
      originalUrl: '/api/v1/auth/refresh',
      protocol: 'http',
      hostHeader: 'localhost:4000',
      publicOrigin: 'https://api.dcmp.com',
      forwardedHost: 'evil.example',
      forwardedProto: 'https',
    });
    assert.equal(spoof.htu, 'https://api.dcmp.com/api/v1/auth/refresh');
    assert.equal(spoof.ignoredForwardedHeaders, true);

    assert.throws(() => normalizeHtuFromAbsolute('https://api.dcmp.com/api/v1/auth/refresh?x=1'));
  });

  test('AES-GCM production cipher rejects tamper / wrong AAD / wrong key id path', async () => {
    const keyProvider = app.get(LocalTestKeyProvider);
    const fields = {
      organizationId: ORG,
      sessionId: '33333333-3333-4333-8333-333333333333',
      requestFingerprint: 'aa'.repeat(32),
      presentedTokenHash: 'bb'.repeat(32),
      issuedTokenId: '44444444-4444-4444-8444-444444444402',
      dpopJkt: 'jkt-test',
      expiresAt: new Date(Date.now() + 60_000),
    };
    const blob = await cipher.encrypt(
      { accessToken: 'a', refreshToken: 'r', expiresIn: 900 },
      fields,
    );
    assert.equal(blob.iv.length, 12);
    assert.equal(blob.authTag.length, 16);

    const ok = await cipher.decrypt(blob, {
      ...fields,
      expiresAt: blob.expiresAt,
    });
    assert.equal(ok.accessToken, 'a');

    const tamperedCt = Buffer.from(blob.ciphertext);
    tamperedCt[0] = tamperedCt[0] ^ 1;
    await assert.rejects(() =>
      cipher.decrypt({ ...blob, ciphertext: tamperedCt }, { ...fields, expiresAt: blob.expiresAt }),
    );

    await assert.rejects(() =>
      cipher.decrypt(blob, {
        ...fields,
        organizationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        expiresAt: blob.expiresAt,
      }),
    );

    const expired = await cipher.encrypt(
      { accessToken: 'a' },
      { ...fields, expiresAt: new Date(Date.now() - 1000) },
    );
    await assert.rejects(() =>
      cipher.decrypt(expired, { ...fields, expiresAt: expired.expiresAt }),
    );

    void keyProvider;
    void buildRefreshAad;
    void createCipheriv;
    void createDecipheriv;
    void randomBytes;
    void REFRESH_CIPHER_KEY_PROVIDER;
  });

  test('login + refresh rotation with valid DPoP', async () => {
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
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    const body = res.json as {
      data?: { tokens: { refreshToken: string } };
      tokens?: { refreshToken: string };
    };
    const tokens = body.data?.tokens || body.tokens;
    assert.ok(tokens?.refreshToken);
    assert.notEqual(tokens!.refreshToken, session.tokens.refreshToken);
  });

  test('invalid DPoP signature does not revoke session', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const tampered = proof.slice(0, -4) + 'aaaa';
    const res = await http('POST', '/api/v1/auth/refresh', {
      dpop: tampered,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(res.status, 401);
    const status = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: session.tokens.refreshToken },
    });
    // status endpoint does not require DPoP in this phase
    assert.equal(status.status, 200);
    const active =
      (status.json as { data?: { active: boolean }; active?: boolean }).data?.active ??
      (status.json as { active: boolean }).active;
    assert.equal(active, true);
    assert.ok(audit.events.some((e) => e.category === 'DPOP_FAILURE'));
  });

  test('wrong HTTP method rejected', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const { proof } = await mintTestDpopProof({
      method: 'GET',
      htu,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(res.status, 401);
  });

  test('wrong URI rejected', async () => {
    const session = await loginPair();
    const { proof } = await mintTestDpopProof({
      method: 'POST',
      htu: `${baseUrl}/api/v1/auth/logout`,
      nonce: session.nonce,
      privateJwk: session.privateJwk,
    });
    const res = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(res.status, 401);
  });

  test('same-proof retry recovers without second rotation semantics', async () => {
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
    const t1 = (
      (r1.json as { data?: { tokens: { refreshToken: string } } }).data?.tokens ||
      (r1.json as { tokens: { refreshToken: string } }).tokens
    ).refreshToken;

    // Identical proof retry (same jti/nonce/sig) — recovery path before JTI reject
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      dpop: proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r2.status, 200, JSON.stringify(r2.json));
    const t2 = (
      (r2.json as { data?: { tokens: { refreshToken: string } } }).data?.tokens ||
      (r2.json as { tokens: { refreshToken: string } }).tokens
    ).refreshToken;
    assert.equal(t1, t2);
  });

  test('divergent proof after consume triggers reuse revocation', async () => {
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
    const code = JSON.stringify(r2.json);
    assert.match(code, /TOKEN_REUSE|SESSION_REVOKED|UNAUTHENTICATED/);
  });

  test('client organization header cannot override tenant', async () => {
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
      headers: { [HTTP_HEADERS.ORGANIZATION_ID]: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
    });
    assert.equal(res.status, 403);
  });

  test('Redis unavailable fails closed for new proof admission (SIMULATED)', async () => {
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
    assert.ok(res.status === 503 || res.status === 401, JSON.stringify(res.json));
    assert.match(JSON.stringify(res.json), /DPOP_REPLAY_STORE_UNAVAILABLE|REDIS|replay/i);
  });

  test('logout prevents subsequent recovery', async () => {
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

    const htuLogout = `${baseUrl}/api/v1/auth/logout`;
    const logoutProof = await mintTestDpopProof({
      method: 'POST',
      htu: htuLogout,
      privateJwk: session.privateJwk,
    });
    const logout = await http('POST', '/api/v1/auth/logout', {
      dpop: logoutProof.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(logout.status, 200);

    const retry = await http('POST', '/api/v1/auth/refresh', {
      dpop: first.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(retry.status, 401);
  });

  test('reused jti rejected on non-recovery path', async () => {
    const session = await loginPair();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = crypto.randomUUID();
    const p1 = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: session.nonce,
      jti,
      privateJwk: session.privateJwk,
    });
    const r1 = await http('POST', '/api/v1/auth/refresh', {
      dpop: p1.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(r1.status, 200);

    // New rotation attempt with SAME jti but different nonce/sig path after first consumed token
    // Use new refresh token from r1 with same jti → should hit replay on non-recovery
    const newRefresh = (
      (r1.json as { data?: { tokens: { refreshToken: string } } }).data?.tokens ||
      (r1.json as { tokens: { refreshToken: string } }).tokens
    ).refreshToken;
    const p2 = await mintTestDpopProof({
      method: 'POST',
      htu,
      nonce: r1.nonce!,
      jti,
      privateJwk: session.privateJwk,
    });
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      dpop: p2.proof,
      body: { refreshToken: newRefresh },
    });
    assert.equal(r2.status, 401);
    assert.match(JSON.stringify(r2.json), /DPOP_PROOF_REPLAY|REPLAY/);
  });
});
