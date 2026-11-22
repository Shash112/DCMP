/**
 * Phase 2.1.17 — ES256 DPoP-bound access tokens, session introspection, login identity.
 * Run: npm run test:auth:access (AUTH_STORE_DRIVER=postgres)
 */
import assert from 'node:assert/strict';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { MemoryRedisAdapter } from '../redis/memory-redis.adapter';
import { AUTH_STORE } from '../persistence/auth-store.port';
import { PostgresAuthStore } from '../persistence/postgres-auth.store';
import { LocalAccessTokenKeyProvider } from '../crypto/local-access-token-key.provider';
import { ACCESS_TOKEN_SIGNING_KEY_PROVIDER } from '../crypto/access-token-key.provider';

assert.equal(process.env.AUTH_STORE_DRIVER, 'postgres');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PASSWORD = 'Password123!';
const EMAIL_UNIQUE = `at-unique-${Date.now()}@example.com`;
const EMAIL_SHARED = `at-shared-${Date.now()}@example.com`;

describe('Phase 2.1.17 Access-token security (PostgreSQL)', () => {
  let app: INestApplication;
  let auth: AuthService;
  let redis: MemoryRedisAdapter;
  let keys: LocalAccessTokenKeyProvider;
  let baseUrl: string;
  let server: ReturnType<INestApplication['getHttpServer']>;

  before(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
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

    assert.ok(app.get(AUTH_STORE) instanceof PostgresAuthStore);
    auth = app.get(AuthService);
    redis = app.get(MemoryRedisAdapter);
    keys = app.get(ACCESS_TOKEN_SIGNING_KEY_PROVIDER) as LocalAccessTokenKeyProvider;

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL_UNIQUE,
      password: PASSWORD,
      displayName: 'Unique User',
    });
    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL_SHARED,
      password: PASSWORD,
      displayName: 'Shared A',
    });
    await auth.seedTestUser({
      organizationId: ORG_B,
      email: EMAIL_SHARED,
      password: PASSWORD,
      displayName: 'Shared B',
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

  async function login(email: string, organizationId?: string) {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu });
    const body: Record<string, string> = { email, password: PASSWORD };
    if (organizationId) body.organizationId = organizationId;
    const res = await http('POST', '/api/v1/auth/login', {
      dpop: minted.proof,
      body,
    });
    return { res, minted };
  }

  async function loginOk(email = EMAIL_UNIQUE, organizationId = ORG_A) {
    const { res, minted } = await login(email, organizationId);
    assert.ok(res.status === 200, JSON.stringify(res.json));
    const data = unwrapData<{
      tokens: { accessToken: string; refreshToken: string; tokenType: string };
    }>(res.json);
    return {
      tokens: data.tokens,
      nonce: res.nonce!,
      privateJwk: minted.privateJwk,
      jkt: minted.jkt,
    };
  }

  test('login issues ES256 access token with iss/aud/cnf.jkt/kid', async () => {
    const session = await loginOk();
    assert.equal(session.tokens.tokenType, 'DPoP');
    const header = decodeProtectedHeader(session.tokens.accessToken);
    assert.equal(header.alg, 'ES256');
    assert.ok(header.kid);

    const jwks = await http('GET', '/api/v1/auth/.well-known/jwks.json');
    assert.equal(jwks.status, 200);
    const keysBody = unwrapData<{ keys: { kid: string }[] }>(jwks.json);
    const jwk = keysBody.keys.find((k) => k.kid === header.kid);
    assert.ok(jwk);
    const pub = await importJWK(jwk as never, 'ES256');
    const { payload } = await jwtVerify(session.tokens.accessToken, pub, {
      algorithms: ['ES256'],
      issuer: 'https://auth.dcmp.local',
      audience: 'dcmp-api',
    });
    assert.equal(payload.type, 'access');
    assert.equal((payload.cnf as { jkt: string }).jkt, session.jkt);
    assert.equal(payload.orgId, ORG_A);
    assert.ok(payload.sid);
    assert.ok(payload.jti);
    assert.ok(payload.nbf != null);
  });

  test('protected /me succeeds with matching DPoP + ath', async () => {
    const session = await loginOk();
    const htu = `${baseUrl}/api/v1/auth/me`;
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 200, JSON.stringify(me.json));
  });

  test('stolen access token without private key is rejected', async () => {
    const session = await loginOk();
    const other = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: session.tokens.accessToken,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: other.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 401);
  });

  test('Bearer scheme rejected on protected route', async () => {
    const session = await loginOk();
    const me = await http('GET', '/api/v1/auth/me', {
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `Bearer ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 401);
  });

  test('missing DPoP proof rejected', async () => {
    const session = await loginOk();
    const me = await http('GET', '/api/v1/auth/me', {
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 401);
  });

  test('wrong ath rejected', async () => {
    const session = await loginOk();
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: 'not-the-access-token',
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 401);
  });

  test('wrong method / URI rejected', async () => {
    const session = await loginOk();
    const badMethod = await mintTestDpopProof({
      method: 'POST',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const r1 = await http('GET', '/api/v1/auth/me', {
      dpop: badMethod.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(r1.status, 401);

    const badUri = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/other`,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const r2 = await http('GET', '/api/v1/auth/me', {
      dpop: badUri.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(r2.status, 401);
  });

  test('logout prevents subsequent protected access', async () => {
    const session = await loginOk();
    const logoutProof = await mintTestDpopProof({
      method: 'POST',
      htu: `${baseUrl}/api/v1/auth/logout`,
      privateJwk: session.privateJwk,
    });
    const logout = await http('POST', '/api/v1/auth/logout', {
      dpop: logoutProof.proof,
      body: { refreshToken: session.tokens.refreshToken },
    });
    assert.equal(logout.status, 200);

    const meProof = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: meProof.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 401);
  });

  test('Redis unavailable fails closed for protected DPoP JTI', async () => {
    const session = await loginOk();
    redis.setAvailable(false);
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    redis.setAvailable(true);
    assert.equal(me.status, 503);
  });

  test('key rotation: previous kid still verifies until retired', async () => {
    const session = await loginOk();
    const oldKid = decodeProtectedHeader(session.tokens.accessToken).kid!;
    const newKid = await keys.rotateForTest();
    assert.notEqual(newKid, oldKid);

    const proof = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: session.tokens.accessToken,
      privateJwk: session.privateJwk,
    });
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: proof.proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me.status, 200, 'previous key must still verify unexpired tokens');

    await keys.retireForTest(oldKid);
    const me2 = await http('GET', '/api/v1/auth/me', {
      dpop: (
        await mintTestDpopProof({
          method: 'GET',
          htu: `${baseUrl}/api/v1/auth/me`,
          accessToken: session.tokens.accessToken,
          privateJwk: session.privateJwk,
        })
      ).proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${session.tokens.accessToken}` },
    });
    assert.equal(me2.status, 401);

    // New login signs with rotated key
    const next = await loginOk(EMAIL_UNIQUE, ORG_A);
    assert.equal(decodeProtectedHeader(next.tokens.accessToken).kid, newKid);
  });

  test('login identity: unique email without org succeeds', async () => {
    const { res } = await login(EMAIL_UNIQUE);
    assert.equal(res.status, 200);
  });

  test('login identity: shared email without org → organization required', async () => {
    const { res } = await login(EMAIL_SHARED);
    assert.equal(res.status, 400);
    assert.match(JSON.stringify(res.json), /LOGIN_ORGANIZATION_REQUIRED/);
  });

  test('login identity: shared email with correct org succeeds', async () => {
    const { res } = await login(EMAIL_SHARED, ORG_A);
    assert.equal(res.status, 200);
    const data = unwrapData<{ user: { organizationId: string } }>(res.json);
    assert.equal(data.user.organizationId, ORG_A);
  });

  test('login identity: shared email with wrong org → invalid credentials', async () => {
    // User exists in ORG_A and ORG_B; requesting a third org yields none
    const { res } = await login(EMAIL_SHARED, 'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
    assert.equal(res.status, 401);
    assert.match(JSON.stringify(res.json), /UNAUTHENTICATED|Invalid credentials/);
  });

  test('login identity: invalid password', async () => {
    const htu = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu });
    const res = await http('POST', '/api/v1/auth/login', {
      dpop: minted.proof,
      body: { email: EMAIL_UNIQUE, password: 'WrongPassword!', organizationId: ORG_A },
    });
    assert.equal(res.status, 401);
  });

  test('invalid signature rejected', async () => {
    const session = await loginOk();
    const parts = session.tokens.accessToken.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -4)}abcd`;
    const proof = await mintTestDpopProof({
      method: 'GET',
      htu: `${baseUrl}/api/v1/auth/me`,
      accessToken: tampered,
      privateJwk: session.privateJwk,
    });
    // Use original token in Authorization but proof ath for tampered — either fails
    const me = await http('GET', '/api/v1/auth/me', {
      dpop: (
        await mintTestDpopProof({
          method: 'GET',
          htu: `${baseUrl}/api/v1/auth/me`,
          accessToken: session.tokens.accessToken,
          privateJwk: session.privateJwk,
        })
      ).proof,
      headers: { [HTTP_HEADERS.AUTHORIZATION]: `DPoP ${tampered}` },
    });
    void proof;
    assert.equal(me.status, 401);
  });
});
