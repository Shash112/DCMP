/**
 * Phase 2.1.23 — Envelope persistence with valid session + live KMS (no CreateKey).
 * Run: npm run test:auth:kms:persist
 */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { ACCESS_TOKEN_SIGNING_KEY_PROVIDER } from '../crypto/access-token-key.provider';
import { KmsAccessTokenKeyProvider } from '../crypto/kms-access-token-key.provider';
import { LocalAccessTokenKeyProvider } from '../crypto/local-access-token-key.provider';
import { RefreshResponseCipher } from '../crypto/refresh-response-cipher';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { AUTH_STORE } from '../persistence/auth-store.port';
import { PostgresAuthStore } from '../persistence/postgres-auth.store';
import { ValidationPgPool } from '../persistence/pg.pool';

assert.equal(process.env.AUTH_CRYPTO_DRIVER, 'kms');
assert.notEqual(process.env.AUTH_ALLOW_LOCAL_KEYS, 'true');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PASSWORD = 'Password123!';
const EMAIL = `kms-persist-${Date.now()}@example.com`;
const EVIDENCE = join(
  process.cwd(),
  '../../infrastructure/database-validation/evidence/phase-2.1.23',
);

type Case = { test_id: string; scenario: string; status: string; detail: string };

describe('Phase 2.1.23 KMS persistence + rotation compat', () => {
  let app: INestApplication;
  let auth: AuthService;
  let cipher: RefreshResponseCipher;
  let accessKeys: KmsAccessTokenKeyProvider;
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
    const sts = new STSClient({ region: process.env.AWS_REGION || 'ap-south-1' });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    assert.equal(id.Account, '980921756876');

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

    assert.throws(() => app.get(LocalAccessTokenKeyProvider));
    accessKeys = app.get(ACCESS_TOKEN_SIGNING_KEY_PROVIDER) as KmsAccessTokenKeyProvider;
    assert.ok(accessKeys instanceof KmsAccessTokenKeyProvider);
    assert.ok(app.get(AUTH_STORE) instanceof PostgresAuthStore);
    cipher = app.get(RefreshResponseCipher);
    pg = app.get(ValidationPgPool);
    auth = app.get(AuthService);

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'KMS Persist',
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
          awsAccount: id.Account,
          region: process.env.AWS_REGION,
          note: 'Persistence via login→refresh; FK session fixture',
        },
        null,
        2,
      ),
    );
  });

  after(async () => {
    writeFileSync(join(EVIDENCE, 'phase_2_1_23_cases.json'), JSON.stringify({ cases }, null, 2));
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
    const tokens = unwrapData<{ tokens: { refreshToken: string; accessToken: string } }>(
      res.json,
    ).tokens;
    return { ...tokens, privateJwk: minted.privateJwk, nonce: res.nonce || '', jkt: minted.jkt };
  }

  test('DB-SEC-KMS-PERSIST-01 envelope encrypted_data_key inserted under valid session FK', async () => {
    const session = await login();
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const jti = randomUUID();
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: session.privateJwk,
      jti,
      nonce: session.nonce || undefined,
    });
    const r1 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: session.refreshToken },
      dpop: proof.proof,
    });
    assert.equal(r1.status, 200, JSON.stringify(r1.json));

    // After rotation, status uses new refresh token (parent session FK already existed from login)
    const newRefresh = unwrapData<{ tokens: { refreshToken: string } }>(r1.json).tokens
      .refreshToken;
    const st2 = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: newRefresh },
    });
    assert.equal(st2.status, 200, JSON.stringify(st2.json));
    const sessionId = unwrapData<{ sessionId: string }>(st2.json).sessionId;
    assert.ok(sessionId, 'sessionId required for FK-backed idempotency row');

    const row = await pg.pool.query(
      `SELECT encryption_key_id, octet_length(encrypted_data_key) AS dek_len,
              octet_length(response_ciphertext) AS ct_len,
              organization_id, session_id, request_fingerprint, presented_token_hash,
              issued_token_id, response_ciphertext, response_iv, response_auth_tag,
              dpop_jkt, expires_at, encrypted_data_key
       FROM public.refresh_idempotency_records
       WHERE organization_id=$1 AND session_id=$2
         AND invalidated_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [ORG_A, sessionId],
    );
    assert.equal(row.rowCount, 1, 'expected idempotency row');
    const recRow = row.rows[0];
    assert.ok(Number(recRow.dek_len) > 0, 'encrypted_data_key must be non-null');
    assert.match(String(recRow.encryption_key_id), /^kms-envelope:/);

    const plain = await cipher.decrypt(
      {
        ciphertext: recRow.response_ciphertext,
        iv: recRow.response_iv,
        authTag: recRow.response_auth_tag,
        encryptionKeyId: recRow.encryption_key_id,
        encryptedDataKey: recRow.encrypted_data_key,
        expiresAt: new Date(recRow.expires_at).toISOString(),
      },
      {
        organizationId: String(recRow.organization_id),
        sessionId: String(recRow.session_id),
        requestFingerprint: String(recRow.request_fingerprint).trim(),
        presentedTokenHash: String(recRow.presented_token_hash).trim(),
        issuedTokenId: String(recRow.issued_token_id),
        dpopJkt: String(recRow.dpop_jkt).trim(),
        expiresAt: new Date(recRow.expires_at).toISOString(),
      },
    );
    assert.ok(plain.refreshToken && plain.accessToken);

    // Idempotent retry with same proof recovers
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: session.refreshToken },
      dpop: proof.proof,
    });
    assert.equal(r2.status, 200);
    const t2 = unwrapData<{ tokens: { refreshToken: string } }>(r2.json).tokens.refreshToken;
    assert.equal(t2, newRefresh);

    rec(
      'DB-SEC-KMS-PERSIST-01',
      'FK session → encrypted_data_key persist + decrypt + idempotent retry',
      true,
      `sessionId=${sessionId.slice(0, 8)}… dek_len=${recRow.dek_len} idempotent=ok`,
    );
  });

  test('DB-SEC-KMS-PERSIST-02 encrypt failure before rotate leaves no idempotency row', async () => {
    const session = await login();
    const before = await pg.pool.query(
      `SELECT count(*)::int AS n FROM public.refresh_idempotency_records WHERE organization_id=$1`,
      [ORG_A],
    );
    const nBefore = before.rows[0].n as number;

    const original = cipher.encrypt.bind(cipher);
    cipher.encrypt = async () => {
      throw new Error('KMS_UNAVAILABLE:SimulatedEncryptFail');
    };
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: session.privateJwk,
      nonce: session.nonce || undefined,
    });
    let status: number;
    try {
      const res = await http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: session.refreshToken },
        dpop: proof.proof,
      });
      status = res.status;
    } finally {
      cipher.encrypt = original;
    }

    const after = await pg.pool.query(
      `SELECT count(*)::int AS n FROM public.refresh_idempotency_records WHERE organization_id=$1`,
      [ORG_A],
    );
    const nAfter = after.rows[0].n as number;
    rec(
      'DB-SEC-KMS-PERSIST-02',
      'Failed encrypt does not insert idempotency (no partial persist)',
      status === 503 && nAfter === nBefore,
      `status=${status} nBefore=${nBefore} nAfter=${nAfter}`,
    );
  });

  test('DB-SEC-KMS-ROTATE-LIVE active signing kid + JWKS; no second live key', async () => {
    const active = await accessKeys.getActiveSigningKey();
    const jwks = await accessKeys.listVerificationJwks();
    const expected = `kms-es256:${process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID}`;
    const verifyList = process.env.DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS || '';
    rec(
      'DB-SEC-KMS-ROTATE-LIVE',
      'Single live ECC key; multi-key live blocked pending provisioning',
      active.kid === expected && jwks.some((k) => k.kid === expected),
      `active=${active.kid} jwks=${jwks.length} verifyListConfigured=${Boolean(verifyList)} liveSecondKey=NOT_RUN`,
    );
  });

  test('DB-SEC-KMS-REFRESH-ALLOWLIST master CMK decrypt accepted', async () => {
    const fields = {
      organizationId: ORG_A,
      sessionId: randomUUID(),
      requestFingerprint: createHash('sha256').update('fp').digest('hex'),
      presentedTokenHash: createHash('sha256').update('pt').digest('hex'),
      issuedTokenId: randomUUID(),
      dpopJkt: 'jkt-allowlist',
      expiresAt: new Date(Date.now() + 60_000),
    };
    const blob = await cipher.encrypt({ marker: true }, fields);
    const plain = await cipher.decrypt(
      { ...blob, encryptedDataKey: blob.encryptedDataKey },
      { ...fields, expiresAt: blob.expiresAt },
    );
    rec(
      'DB-SEC-KMS-REFRESH-ALLOWLIST',
      'Decrypt under active master CMK passes allowlist',
      plain.marker === true,
      `encryptionKeyId=${blob.encryptionKeyId}`,
    );
  });
});
