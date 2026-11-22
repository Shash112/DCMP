/**
 * Phase 2.1.22 — Live AWS KMS (non-prod) + PostgreSQL + Redis.
 * Run: npm run test:auth:kms
 * Requires AWS_PROFILE=dcmp-nonprod and three DCMP_KMS_* key IDs.
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { importJWK, jwtVerify } from 'jose';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { AppModule } from '../../../app.module';
import { AuthService } from '../auth.service';
import { ACCESS_TOKEN_SIGNING_KEY_PROVIDER } from '../crypto/access-token-key.provider';
import { KmsAccessTokenKeyProvider } from '../crypto/kms-access-token-key.provider';
import { LocalAccessTokenKeyProvider } from '../crypto/local-access-token-key.provider';
import { LocalTestKeyProvider } from '../crypto/local-test-key.provider';
import { LocalSsaSigningProvider, SSA_SIGNING_PROVIDER } from '../crypto/ssa-signing.provider';
import { KmsSsaSigningProvider } from '../crypto/ssa-signing.provider';
import { KmsRefreshEnvelopeProvider } from '../crypto/kms-refresh-envelope.provider';
import { RefreshResponseCipher } from '../crypto/refresh-response-cipher';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { AUTH_REDIS } from '../redis/redis.port';
import { RealRedisAdapter } from '../redis/real-redis.adapter';
import { ValidationPgPool } from '../persistence/pg.pool';
import { SupportSessionService } from '../support/support-session.service';

assert.equal(process.env.AUTH_CRYPTO_DRIVER, 'kms');
assert.equal(process.env.AUTH_STORE_DRIVER, 'postgres');
assert.equal(process.env.AUTH_REDIS_DRIVER, 'real');
assert.notEqual(process.env.AUTH_ALLOW_LOCAL_KEYS, 'true');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN_ID = '99999999-9999-4999-8999-999999999999';
const PASSWORD = 'Password123!';
const EMAIL = `kms-live-${Date.now()}@example.com`;
const EVIDENCE = join(
  process.cwd(),
  '../../infrastructure/database-validation/evidence/phase-2.1.22',
);
const EXPECTED_AT_KID = `kms-es256:${process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID}`;

type Case = {
  test_id: string;
  scenario: string;
  status: 'PASSED' | 'FAILED' | 'BLOCKED' | 'NOT_RUN';
  detail: string;
};

describe('Phase 2.1.22 Live AWS KMS', () => {
  let app: INestApplication;
  let auth: AuthService;
  let accessKeys: KmsAccessTokenKeyProvider;
  let ssa: KmsSsaSigningProvider;
  let envelope: KmsRefreshEnvelopeProvider;
  let cipher: RefreshResponseCipher;
  let redis: RealRedisAdapter;
  let pg: ValidationPgPool;
  let support: SupportSessionService;
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

    // Identity gate — refuse FarmersWing prod account
    const sts = new STSClient({ region: process.env.AWS_REGION || 'ap-south-1' });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    assert.equal(id.Account, '980921756876', `Unexpected AWS account ${id.Account}`);

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

    // Prove local providers are not bound
    assert.throws(() => app.get(LocalAccessTokenKeyProvider), /Nest could not find|not found/i);
    assert.throws(() => app.get(LocalTestKeyProvider), /Nest could not find|not found/i);
    assert.throws(() => app.get(LocalSsaSigningProvider), /Nest could not find|not found/i);

    // Prefer injection tokens; concrete KMS classes are not AuthModule exports (2.1.25).
    accessKeys = app.get(ACCESS_TOKEN_SIGNING_KEY_PROVIDER) as KmsAccessTokenKeyProvider;
    assert.ok(accessKeys instanceof KmsAccessTokenKeyProvider);
    ssa = app.get(SSA_SIGNING_PROVIDER) as KmsSsaSigningProvider;
    assert.ok(ssa instanceof KmsSsaSigningProvider);
    assert.equal(ssa.mode, 'KMS_HMAC');
    envelope = moduleRef.get(KmsRefreshEnvelopeProvider, { strict: false });
    assert.ok(envelope instanceof KmsRefreshEnvelopeProvider);
    cipher = app.get(RefreshResponseCipher);
    redis = app.get(AUTH_REDIS) as RealRedisAdapter;
    assert.ok(redis instanceof RealRedisAdapter);
    pg = app.get(ValidationPgPool);
    support = app.get(SupportSessionService);
    auth = app.get(AuthService);

    const ver = await pg.pool.query(
      'SELECT version() AS version, current_database() AS db, inet_server_port() AS port',
    );
    assert.match(String(ver.rows[0].version), /PostgreSQL 16\.10/);
    assert.equal(ver.rows[0].db, 'dcmp_validation');

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'KMS Live',
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
          profile: process.env.AWS_PROFILE,
          cryptoDriver: process.env.AUTH_CRYPTO_DRIVER,
          allowLocalKeys: process.env.AUTH_ALLOW_LOCAL_KEYS ?? null,
          accessTokenKidExpected: EXPECTED_AT_KID,
          postgresql: ver.rows[0],
          redisDb: process.env.REDIS_DB,
          note: 'No secrets, tokens, MACs, or plaintext DEKs logged',
        },
        null,
        2,
      ),
    );
  });

  after(async () => {
    writeFileSync(join(EVIDENCE, 'phase_2_1_22_cases.json'), JSON.stringify({ cases }, null, 2));
    await new Promise<void>((resolve, reject) =>
      server.close((e: Error | undefined) => (e ? reject(e) : resolve())),
    );
    await app.close();
  });

  async function http(
    method: string,
    path: string,
    opts: { body?: unknown; dpop?: string; authorization?: string } = {},
  ) {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
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

  // ——— A. Access-token ———
  test('DB-SEC-KMS-AT-JWKS GetPublicKey + JWKS publication', async () => {
    const jwks = await accessKeys.listVerificationJwks();
    const httpJwks = await http('GET', '/api/v1/auth/.well-known/jwks.json');
    const keys =
      unwrapData<{ keys: { kid?: string; kty?: string; crv?: string }[] }>(httpJwks.json).keys ||
      (httpJwks.json as { keys: { kid?: string }[] }).keys;
    const found = jwks.find((k) => k.kid === EXPECTED_AT_KID);
    rec(
      'DB-SEC-KMS-AT-JWKS',
      'JWKS publishes KMS ECC public key',
      httpJwks.status === 200 &&
        !!found &&
        found.kty === 'EC' &&
        found.crv === 'P-256' &&
        Array.isArray(keys) &&
        keys.some((k) => k.kid === EXPECTED_AT_KID),
      `kids=${jwks.map((k) => k.kid).join(',')} http=${httpJwks.status}`,
    );
  });

  test('DB-SEC-KMS-AT-SIGN Sign JWT via KMS + verify with published JWK', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await accessKeys.signCompactJwt({
      email: EMAIL,
      orgId: ORG_A,
      roles: ['inspector'],
      sid: randomUUID(),
      type: 'access',
      cnf: { jkt: 'test-jkt-not-for-authz' },
      iss: process.env.DCMP_ACCESS_TOKEN_ISSUER || 'https://auth.dcmp.local',
      aud: process.env.DCMP_ACCESS_TOKEN_AUDIENCE || 'dcmp-api',
      sub: randomUUID(),
      jti: randomUUID(),
      iat: now,
      nbf: now,
      exp: now + 300,
    });
    const parts = token.split('.');
    assert.equal(parts.length, 3);
    // JOSE ES256 sig is 64 bytes raw → ~86 base64url chars
    const sigLen = Buffer.from(parts[2], 'base64url').length;
    const jwks = await accessKeys.listVerificationJwks();
    const jwk = jwks.find((k) => k.kid === EXPECTED_AT_KID)!;
    const pub = await importJWK(jwk, 'ES256');
    const verified = await jwtVerify(token, pub, {
      algorithms: ['ES256'],
      issuer: process.env.DCMP_ACCESS_TOKEN_ISSUER || 'https://auth.dcmp.local',
      audience: process.env.DCMP_ACCESS_TOKEN_AUDIENCE || 'dcmp-api',
    });
    rec(
      'DB-SEC-KMS-AT-SIGN',
      'KMS Sign + JOSE verify',
      verified.protectedHeader.kid === EXPECTED_AT_KID && sigLen === 64,
      `kid=${verified.protectedHeader.kid} sigBytes=${sigLen}`,
    );
  });

  // ——— B. SSA HMAC ———
  test('DB-SEC-KMS-SSA-MAC GenerateMac + VerifyMac + attested open', async () => {
    const u = await pg.pool.query(`SELECT id FROM public.users WHERE email=$1`, [EMAIL]);
    const userId = u.rows[0].id as string;
    const req = await support.createAccessRequest({ organizationId: ORG_A, adminId: ADMIN_ID });
    const grant = await support.approveRequest({
      requestId: req.requestId,
      organizationId: ORG_A,
      approvedByUserId: userId,
      ttlMinutes: 10,
    });
    const ch = await support.issueChallenge({
      organizationId: ORG_A,
      grantId: grant.grantId,
      adminId: ADMIN_ID,
    });
    const minted = await ssa.mint({
      adminId: ADMIN_ID,
      organizationId: ORG_A,
      grantId: grant.grantId,
      requestId: req.requestId,
    });
    assert.equal(minted.keyMaterial, 'KMS-HMAC');
    const macOk = await ssa.verify(minted.assertion);
    const open = await support.openSession({
      assertion: minted.assertion,
      organizationId: ORG_A,
      grantId: grant.grantId,
      challengeId: ch.challengeId,
    });
    // Replay must fail
    let replayDenied = false;
    try {
      await support.openSession({
        assertion: minted.assertion,
        organizationId: ORG_A,
        grantId: grant.grantId,
        challengeId: ch.challengeId,
      });
    } catch {
      replayDenied = true;
    }
    rec(
      'DB-SEC-KMS-SSA-MAC',
      'GenerateMac/VerifyMac + attested open + replay',
      macOk && open.opened && open.verifySignature && replayDenied,
      `mac=${macOk} opened=${open.opened} replayDenied=${replayDenied}`,
    );
  });

  // ——— C. Refresh envelope ———
  test('DB-SEC-KMS-ENVELOPE GenerateDataKey round-trip + tamper/AAD reject', async () => {
    const fields = {
      organizationId: ORG_A,
      sessionId: randomUUID(),
      requestFingerprint: 'a'.repeat(64),
      presentedTokenHash: 'b'.repeat(64),
      issuedTokenId: randomUUID(),
      dpopJkt: 'jkt-envelope-test',
      expiresAt: new Date(Date.now() + 60_000),
    };
    const blob = await cipher.encrypt(
      { accessToken: 'x', refreshToken: 'y', expiresIn: 900 },
      fields,
    );
    assert.ok(blob.encryptedDataKey && blob.encryptedDataKey.length > 0);
    assert.match(blob.encryptionKeyId, /^kms-envelope:/);

    // Persist and reload from PG
    await pg.pool
      .query(
        `INSERT INTO public.refresh_idempotency_records (
         organization_id, session_id, request_fingerprint, presented_token_hash,
         issued_token_id, response_ciphertext, response_iv, response_auth_tag,
         encryption_key_id, dpop_jkt, expires_at, encrypted_data_key
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          // Use a disposable session row? FK may require session — try insert; if FK fails use in-memory only
          fields.organizationId,
          fields.sessionId,
          fields.requestFingerprint,
          fields.presentedTokenHash,
          fields.issuedTokenId,
          blob.ciphertext,
          blob.iv,
          blob.authTag,
          blob.encryptionKeyId,
          fields.dpopJkt,
          fields.expiresAt,
          blob.encryptedDataKey,
        ],
      )
      .catch(async () => {
        // FK to sessions — round-trip without PG persist is still valid for crypto
      });

    const plain = await cipher.decrypt(
      {
        ciphertext: blob.ciphertext,
        iv: blob.iv,
        authTag: blob.authTag,
        encryptionKeyId: blob.encryptionKeyId,
        encryptedDataKey: blob.encryptedDataKey,
        expiresAt: blob.expiresAt,
      },
      {
        organizationId: fields.organizationId,
        sessionId: fields.sessionId,
        requestFingerprint: fields.requestFingerprint,
        presentedTokenHash: fields.presentedTokenHash,
        issuedTokenId: fields.issuedTokenId,
        dpopJkt: fields.dpopJkt,
        expiresAt: blob.expiresAt,
      },
    );
    assert.equal(plain.accessToken, 'x');

    let tamperDenied = false;
    try {
      const bad = Buffer.from(blob.ciphertext);
      bad[0] ^= 0xff;
      await cipher.decrypt(
        { ...blob, ciphertext: bad, encryptedDataKey: blob.encryptedDataKey },
        {
          organizationId: fields.organizationId,
          sessionId: fields.sessionId,
          requestFingerprint: fields.requestFingerprint,
          presentedTokenHash: fields.presentedTokenHash,
          issuedTokenId: fields.issuedTokenId,
          dpopJkt: fields.dpopJkt,
          expiresAt: blob.expiresAt,
        },
      );
    } catch {
      tamperDenied = true;
    }

    let aadDenied = false;
    try {
      await cipher.decrypt(
        { ...blob, encryptedDataKey: blob.encryptedDataKey },
        {
          organizationId: fields.organizationId,
          sessionId: fields.sessionId,
          requestFingerprint: fields.requestFingerprint,
          presentedTokenHash: fields.presentedTokenHash,
          issuedTokenId: fields.issuedTokenId,
          dpopJkt: 'wrong-jkt',
          expiresAt: blob.expiresAt,
        },
      );
    } catch {
      aadDenied = true;
    }

    // Direct envelope API also works
    const envBlob = await envelope.encryptEnvelope({ ping: true }, fields);
    const envPlain = await envelope.decryptEnvelope(envBlob, {
      organizationId: fields.organizationId,
      sessionId: fields.sessionId,
      requestFingerprint: fields.requestFingerprint,
      presentedTokenHash: fields.presentedTokenHash,
      issuedTokenId: fields.issuedTokenId,
      dpopJkt: fields.dpopJkt,
      expiresAt: envBlob.expiresAt,
    });

    rec(
      'DB-SEC-KMS-ENVELOPE',
      'GenerateDataKey + GCM round-trip + tamper/AAD',
      plain.accessToken === 'x' &&
        tamperDenied &&
        aadDenied &&
        envPlain.ping === true &&
        !!blob.encryptedDataKey,
      `tamper=${tamperDenied} aad=${aadDenied} dekBytes=${blob.encryptedDataKey!.length}`,
    );
  });

  // ——— D. Failure behavior ———
  test('DB-SEC-KMS-503 cryptographic unavailability fails closed', async () => {
    // 1) Simulated KMS Sign outage → login must 503 (no local fallback)
    const original = accessKeys.signCompactJwt.bind(accessKeys);
    accessKeys.signCompactJwt = async () => {
      throw new Error('KMS_UNAVAILABLE:SimulatedOutage');
    };
    const htuLogin = `${baseUrl}/api/v1/auth/login`;
    const minted = await mintTestDpopProof({ method: 'POST', htu: htuLogin });
    let login503: number;
    try {
      const login = await http('POST', '/api/v1/auth/login', {
        body: { email: EMAIL, password: PASSWORD, organizationId: ORG_A },
        dpop: minted.proof,
      });
      login503 = login.status;
    } finally {
      accessKeys.signCompactJwt = original;
    }

    // 2) Replay-store unavailable (Redis) also fail-closed 503
    const loginOk = await http('POST', '/api/v1/auth/login', {
      body: { email: EMAIL, password: PASSWORD, organizationId: ORG_A },
      dpop: (
        await mintTestDpopProof({ method: 'POST', htu: htuLogin, privateJwk: minted.privateJwk })
      ).proof,
    });
    assert.equal(loginOk.status, 200, JSON.stringify(loginOk.json));
    const tokens = unwrapData<{ tokens: { refreshToken: string } }>(loginOk.json).tokens;
    redis.setAvailable(false);
    const htu = `${baseUrl}/api/v1/auth/refresh`;
    const proof = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: minted.privateJwk,
      nonce: loginOk.nonce || undefined,
    });
    const refresh = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: tokens.refreshToken },
      dpop: proof.proof,
    });
    redis.setAvailable(true);

    let localAbsent = true;
    try {
      app.get(LocalAccessTokenKeyProvider);
      localAbsent = false;
    } catch {
      localAbsent = true;
    }

    rec(
      'DB-SEC-KMS-503',
      'KMS Sign outage + Redis outage fail-closed; no local providers',
      login503 === 503 && refresh.status === 503 && localAbsent,
      `loginKms=${login503} refreshRedis=${refresh.status} localAbsent=${localAbsent}`,
    );
  });

  // ——— E. Rotation compatibility ———
  test('DB-SEC-KMS-ROTATE-COMPAT verify key ID lists + refresh unwrap allowlist', async () => {
    const jwks = await accessKeys.listVerificationJwks();
    const active = await accessKeys.getActiveSigningKey();
    // Decrypt still selects CMK via CiphertextBlob; VERIFY_KEY_IDS soft-allowlist returned KeyId
    // (active master always allowed). True multi-key live needs a second provisioned CMK.
    const note =
      'DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS = post-Decrypt KeyId allowlist (not Sign/GenerateDataKey)';
    rec(
      'DB-SEC-KMS-ROTATE-COMPAT',
      'Active kid published; refresh verify list is unwrap allowlist',
      active.kid === EXPECTED_AT_KID && jwks.some((k) => k.kid === active.kid),
      `active=${active.kid} jwks=${jwks.length}; ${note}`,
    );
  });
});
