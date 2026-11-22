/**
 * Phase 2.1.24 — Live AWS KMS multi-key rotation (non-prod).
 * Run: npm run test:auth:kms:multikey
 *
 * Requires env (prior keys — do not hardcode in committed source):
 *   DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID
 *   DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID
 *   DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID
 * plus AWS_PROFILE=dcmp-nonprod, Redis, PG 16.10 validation DB.
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
import {
  LocalSsaSigningProvider,
  SSA_SIGNING_PROVIDER,
  KmsSsaSigningProvider,
} from '../crypto/ssa-signing.provider';
import { KmsRefreshEnvelopeProvider } from '../crypto/kms-refresh-envelope.provider';
import { RefreshResponseCipher } from '../crypto/refresh-response-cipher';
import { mintTestDpopProof } from '../dpop/dpop.validator';
import { AUTH_STORE } from '../persistence/auth-store.port';
import { PostgresAuthStore } from '../persistence/postgres-auth.store';
import { ValidationPgPool } from '../persistence/pg.pool';
import { SupportSessionService } from '../support/support-session.service';

assert.equal(process.env.AUTH_CRYPTO_DRIVER, 'kms');
assert.notEqual(process.env.AUTH_ALLOW_LOCAL_KEYS, 'true');

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN_ID = '99999999-9999-4999-8999-999999999999';
const PASSWORD = 'Password123!';
const EMAIL = `kms-multikey-${Date.now()}@example.com`;
const EVIDENCE = join(
  process.cwd(),
  '../../infrastructure/database-validation/evidence/phase-2.1.24',
);

const ACTIVE_AT = process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID!;
const PRIOR_AT = process.env.DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID!;
const ACTIVE_SSA = process.env.DCMP_KMS_SSA_HMAC_KEY_ID!;
const PRIOR_SSA = process.env.DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID!;
const ACTIVE_REFRESH = process.env.DCMP_KMS_REFRESH_MASTER_KEY_ID!;
const PRIOR_REFRESH = process.env.DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID!;

const ACTIVE_AT_KID = `kms-es256:${ACTIVE_AT}`;
const PRIOR_AT_KID = `kms-es256:${PRIOR_AT}`;
const ACTIVE_SSA_KID = `kms-hmac256:${ACTIVE_SSA}`;
const PRIOR_SSA_KID = `kms-hmac256:${PRIOR_SSA}`;
const ISSUER = process.env.DCMP_ACCESS_TOKEN_ISSUER || 'https://auth.dcmp.local';
const AUDIENCE = process.env.DCMP_ACCESS_TOKEN_AUDIENCE || 'dcmp-api';

type Case = {
  test_id: string;
  scenario: string;
  status: string;
  detail: string;
  live_aws: boolean;
};

describe('Phase 2.1.24 Live multi-key KMS rotation', () => {
  let app: INestApplication;
  let auth: AuthService;
  let accessKeys: KmsAccessTokenKeyProvider;
  let ssa: KmsSsaSigningProvider;
  let envelope: KmsRefreshEnvelopeProvider;
  let cipher: RefreshResponseCipher;
  let pg: ValidationPgPool;
  let support: SupportSessionService;
  let baseUrl: string;
  let server: ReturnType<INestApplication['getHttpServer']>;
  const cases: Case[] = [];

  function rec(
    test_id: string,
    scenario: string,
    passed: boolean,
    detail: string,
    live_aws = true,
  ) {
    cases.push({
      test_id,
      scenario,
      status: passed ? 'PASSED' : 'FAILED',
      detail: detail.slice(0, 500),
      live_aws,
    });
    assert.ok(passed, `${test_id}: ${detail}`);
  }

  before(async () => {
    mkdirSync(EVIDENCE, { recursive: true });
    assert.ok(PRIOR_AT && PRIOR_SSA && PRIOR_REFRESH, 'prior key env required');
    assert.notEqual(PRIOR_AT, ACTIVE_AT);
    assert.notEqual(PRIOR_SSA, ACTIVE_SSA);
    assert.notEqual(PRIOR_REFRESH, ACTIVE_REFRESH);

    const sts = new STSClient({ region: process.env.AWS_REGION || 'ap-south-1' });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    assert.equal(id.Account, '980921756876', `Unexpected AWS account ${id.Account}`);
    assert.ok(String(id.Arn || '').includes('dcmp-kms-dev') || id.Account === '980921756876');

    writeFileSync(
      join(EVIDENCE, '00_environment.json'),
      JSON.stringify(
        {
          awsAccount: id.Account,
          region: process.env.AWS_REGION,
          profile: process.env.AWS_PROFILE,
          activeKeyPurposes: ['access-token', 'ssa-hmac', 'refresh-master'],
          priorKeysConfigured: true,
          note: 'Key UUID values intentionally omitted from evidence',
        },
        null,
        2,
      ),
    );

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
    assert.throws(() => app.get(LocalTestKeyProvider));
    assert.throws(() => app.get(LocalSsaSigningProvider));

    // Prefer injection tokens; concrete KMS classes are not AuthModule exports (2.1.25).
    accessKeys = app.get(ACCESS_TOKEN_SIGNING_KEY_PROVIDER) as KmsAccessTokenKeyProvider;
    assert.ok(accessKeys instanceof KmsAccessTokenKeyProvider);
    ssa = app.get(SSA_SIGNING_PROVIDER) as KmsSsaSigningProvider;
    assert.ok(ssa instanceof KmsSsaSigningProvider);
    envelope = moduleRef.get(KmsRefreshEnvelopeProvider, { strict: false });
    assert.ok(envelope instanceof KmsRefreshEnvelopeProvider);
    cipher = app.get(RefreshResponseCipher);
    assert.ok(app.get(AUTH_STORE) instanceof PostgresAuthStore);
    pg = app.get(ValidationPgPool);
    support = app.get(SupportSessionService);
    auth = app.get(AuthService);

    await auth.seedTestUser({
      organizationId: ORG_A,
      email: EMAIL,
      password: PASSWORD,
      displayName: 'KMS Multikey',
    });

    server = app.getHttpServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no address');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    // Restore active keys if tests mutated them
    try {
      await accessKeys.rotateForTest(ACTIVE_AT);
    } catch {
      /* ignore */
    }
    try {
      ssa.setActiveHmacKeyIdForTest(ACTIVE_SSA);
    } catch {
      /* ignore */
    }
    try {
      envelope.setActiveMasterKeyIdForTest(ACTIVE_REFRESH);
    } catch {
      /* ignore */
    }
    writeFileSync(join(EVIDENCE, 'phase_2_1_24_cases.json'), JSON.stringify({ cases }, null, 2));
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

  async function signAccess(kidHint?: string) {
    const now = Math.floor(Date.now() / 1000);
    const token = await accessKeys.signCompactJwt({
      email: EMAIL,
      orgId: ORG_A,
      roles: ['inspector'],
      sid: randomUUID(),
      type: 'access',
      cnf: { jkt: 'multikey-jkt' },
      iss: ISSUER,
      aud: AUDIENCE,
      sub: randomUUID(),
      jti: randomUUID(),
      iat: now,
      nbf: now,
      exp: now + 300,
    });
    if (kidHint) {
      const hdr = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8')) as {
        kid: string;
      };
      assert.equal(hdr.kid, kidHint);
    }
    return token;
  }

  async function verifyToken(token: string, kid: string) {
    const key = await accessKeys.getVerificationKey(kid);
    assert.ok(key, `missing verification key ${kid}`);
    return jwtVerify(token, await importJWK(key!.publicJwk, 'ES256'), {
      algorithms: ['ES256'],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
  }

  // ——— 1. Access-token rotation ———
  test('DB-SEC-KMS-MK-AT prior Sign then active rotate; both verify; JWKS; rejects', async () => {
    // Sign with PRIOR via rotateForTest (live KMS Sign)
    const priorKid = await accessKeys.rotateForTest(PRIOR_AT);
    assert.equal(priorKid, PRIOR_AT_KID);
    const priorToken = await signAccess(PRIOR_AT_KID);

    // Switch active back to ORIGINAL; PRIOR remains in verify set
    const activeKid = await accessKeys.rotateForTest(ACTIVE_AT);
    assert.equal(activeKid, ACTIVE_AT_KID);
    const activeToken = await signAccess(ACTIVE_AT_KID);

    const vPrior = await verifyToken(priorToken, PRIOR_AT_KID);
    const vActive = await verifyToken(activeToken, ACTIVE_AT_KID);
    assert.equal(vPrior.protectedHeader.kid, PRIOR_AT_KID);
    assert.equal(vActive.protectedHeader.kid, ACTIVE_AT_KID);

    const jwks = await accessKeys.listVerificationJwks();
    assert.ok(jwks.some((k) => k.kid === PRIOR_AT_KID));
    assert.ok(jwks.some((k) => k.kid === ACTIVE_AT_KID));

    const httpJwks = await http('GET', '/api/v1/auth/.well-known/jwks.json');
    const keys = unwrapData<{ keys: { kid: string }[] }>(httpJwks.json).keys;
    assert.ok(keys.some((k) => k.kid === PRIOR_AT_KID));
    assert.ok(keys.some((k) => k.kid === ACTIVE_AT_KID));

    // Invalid signature rejected
    const parts = activeToken.split('.');
    const badSig = parts[0] + '.' + parts[1] + '.' + parts[2].slice(0, -4) + 'xxxx';
    let badSigDenied = false;
    try {
      await verifyToken(badSig, ACTIVE_AT_KID);
    } catch {
      badSigDenied = true;
    }

    // Unknown kid rejected
    const unknown = await accessKeys.getVerificationKey(
      'kms-es256:00000000-0000-0000-0000-000000000000',
    );
    assert.equal(unknown, null);

    // No local fallback
    assert.throws(() => app.get(LocalAccessTokenKeyProvider));

    rec(
      'DB-SEC-KMS-MK-AT',
      'Live ECC prior+active Sign/verify + JWKS + reject invalid/unknown',
      badSigDenied && unknown === null,
      `priorKid=${PRIOR_AT_KID.slice(0, 20)}… activeKid=${ACTIVE_AT_KID.slice(0, 20)}… jwks=${jwks.length}`,
    );
  });

  // ——— 2. SSA HMAC rotation ———
  test('DB-SEC-KMS-MK-SSA prior GenerateMac then active switch; verify + replay', async () => {
    const u = await pg.pool.query(`SELECT id FROM public.users WHERE email=$1`, [EMAIL]);
    const userId = u.rows[0].id as string;

    // Mint under PRIOR (live GenerateMac)
    ssa.setActiveHmacKeyIdForTest(PRIOR_SSA);
    assert.equal(ssa.activeKid(), PRIOR_SSA_KID);
    const req = await support.createAccessRequest({ organizationId: ORG_A, adminId: ADMIN_ID });
    const grant = await support.approveRequest({
      requestId: req.requestId,
      organizationId: ORG_A,
      approvedByUserId: userId,
      ttlMinutes: 10,
    });
    const priorMint = await ssa.mint({
      adminId: ADMIN_ID,
      organizationId: ORG_A,
      grantId: grant.grantId,
      requestId: req.requestId,
    });
    assert.equal(priorMint.kid, PRIOR_SSA_KID);
    assert.equal(priorMint.keyMaterial, 'KMS-HMAC');

    // Switch active to ORIGINAL; PRIOR remains in VERIFY list
    ssa.setActiveHmacKeyIdForTest(ACTIVE_SSA);
    assert.equal(ssa.activeKid(), ACTIVE_SSA_KID);

    const priorStillValid = await ssa.verify(priorMint.assertion);
    assert.equal(priorStillValid, true);

    const activeMint = await ssa.mint({
      adminId: ADMIN_ID,
      organizationId: ORG_A,
      grantId: grant.grantId,
      requestId: req.requestId,
    });
    assert.equal(activeMint.kid, ACTIVE_SSA_KID);
    assert.equal(await ssa.verify(activeMint.assertion), true);

    // Invalid MAC rejected
    const badParts = priorMint.assertion.split('.');
    const badMac = `${badParts[0]}.${badParts[1]}.${badParts[2].slice(0, -4)}zzzz`;
    assert.equal(await ssa.verify(badMac), false);

    // Attested open with PRIOR assertion + replay deny
    const ch = await support.issueChallenge({
      organizationId: ORG_A,
      grantId: grant.grantId,
      adminId: ADMIN_ID,
    });
    const open = await support.openSession({
      assertion: priorMint.assertion,
      organizationId: ORG_A,
      grantId: grant.grantId,
      challengeId: ch.challengeId,
    });
    let replayDenied = false;
    try {
      await support.openSession({
        assertion: priorMint.assertion,
        organizationId: ORG_A,
        grantId: grant.grantId,
        challengeId: ch.challengeId,
      });
    } catch {
      replayDenied = true;
    }

    rec(
      'DB-SEC-KMS-MK-SSA',
      'Live HMAC prior MAC survives active switch; invalid+replay denied',
      priorStillValid && open.opened && open.verifySignature && replayDenied,
      `priorKid=${PRIOR_SSA_KID.slice(0, 22)}… activeKid=${ACTIVE_SSA_KID.slice(0, 22)}… replay=${replayDenied}`,
    );
  });

  // ——— 3. Refresh master persisted envelope rotation ———
  test('DB-SEC-KMS-MK-REFRESH persist under prior CMK; decrypt after active switch', async () => {
    // Ensure original is active, then switch to PRIOR for encrypt
    envelope.setActiveMasterKeyIdForTest(PRIOR_REFRESH);
    assert.equal(envelope.activeMasterKeyIdForTest(), PRIOR_REFRESH);

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
    const newRefresh = unwrapData<{ tokens: { refreshToken: string } }>(r1.json).tokens
      .refreshToken;

    const st = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: newRefresh },
    });
    const sessionId = unwrapData<{ sessionId: string }>(st.json).sessionId;

    const row = await pg.pool.query(
      `SELECT encryption_key_id, octet_length(encrypted_data_key) AS dek_len,
              organization_id, session_id, request_fingerprint, presented_token_hash,
              issued_token_id, response_ciphertext, response_iv, response_auth_tag,
              dpop_jkt, expires_at, encrypted_data_key
       FROM public.refresh_idempotency_records
       WHERE organization_id=$1 AND session_id=$2 AND invalidated_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [ORG_A, sessionId],
    );
    assert.equal(row.rowCount, 1);
    const recRow = row.rows[0];
    assert.ok(Number(recRow.dek_len) > 0);
    assert.match(String(recRow.encryption_key_id), new RegExp(`kms-envelope:${PRIOR_REFRESH}`));

    // Switch active refresh master to ORIGINAL; prior remains in VERIFY allowlist
    envelope.setActiveMasterKeyIdForTest(ACTIVE_REFRESH);
    assert.equal(envelope.activeMasterKeyIdForTest(), ACTIVE_REFRESH);

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

    // Idempotent retry recovers same tokens via prior-wrapped DEK under new active
    const r2 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: session.refreshToken },
      dpop: proof.proof,
    });
    assert.equal(r2.status, 200, JSON.stringify(r2.json));
    const t2 = unwrapData<{ tokens: { refreshToken: string } }>(r2.json).tokens.refreshToken;
    assert.equal(t2, newRefresh);

    // Fresh rotation under ORIGINAL master
    const proof2 = await mintTestDpopProof({
      method: 'POST',
      htu,
      privateJwk: session.privateJwk,
      nonce: r2.nonce || undefined,
    });
    const r3 = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: newRefresh },
      dpop: proof2.proof,
    });
    assert.equal(r3.status, 200, JSON.stringify(r3.json));
    const newer = unwrapData<{ tokens: { refreshToken: string } }>(r3.json).tokens.refreshToken;
    const st3 = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: newer },
    });
    const sid3 = unwrapData<{ sessionId: string }>(st3.json).sessionId;
    const row3 = await pg.pool.query(
      `SELECT encryption_key_id FROM public.refresh_idempotency_records
       WHERE organization_id=$1 AND session_id=$2 AND invalidated_at IS NULL
       ORDER BY created_at DESC LIMIT 1`,
      [ORG_A, sid3],
    );
    assert.match(
      String(row3.rows[0].encryption_key_id),
      new RegExp(`kms-envelope:${ACTIVE_REFRESH}`),
    );

    // Encrypt failure → 503, no partial new row for a fresh session
    const sessionB = await login();
    const before = await pg.pool.query(
      `SELECT count(*)::int AS n FROM public.refresh_idempotency_records WHERE organization_id=$1`,
      [ORG_A],
    );
    const nBefore = before.rows[0].n as number;
    const originalEncrypt = cipher.encrypt.bind(cipher);
    cipher.encrypt = async () => {
      throw new Error('KMS_UNAVAILABLE:SimulatedEncryptFail');
    };
    let failStatus: number;
    try {
      const pf = await mintTestDpopProof({
        method: 'POST',
        htu,
        privateJwk: sessionB.privateJwk,
        nonce: sessionB.nonce || undefined,
      });
      const fail = await http('POST', '/api/v1/auth/refresh', {
        body: { refreshToken: sessionB.refreshToken },
        dpop: pf.proof,
      });
      failStatus = fail.status;
    } finally {
      cipher.encrypt = originalEncrypt;
    }
    const after = await pg.pool.query(
      `SELECT count(*)::int AS n FROM public.refresh_idempotency_records WHERE organization_id=$1`,
      [ORG_A],
    );
    assert.equal(failStatus!, 503);
    assert.equal(after.rows[0].n, nBefore);

    rec(
      'DB-SEC-KMS-MK-REFRESH',
      'Persist under prior CMK; decrypt+idempotent after switch; new under active; 503 no partial',
      true,
      `session=${String(sessionId).slice(0, 8)}… priorLabel=ok activeLabel=ok idempotent=ok fail503=ok`,
    );
  });

  // ——— 4. Fail-closed / isolation smoke ———
  test('DB-SEC-KMS-MK-FAILCLOSED no local providers; KMS sign outage 503; DPoP enforced', async () => {
    assert.throws(() => app.get(LocalAccessTokenKeyProvider));
    assert.throws(() => app.get(LocalSsaSigningProvider));

    const originalSign = accessKeys.signCompactJwt.bind(accessKeys);
    accessKeys.signCompactJwt = async () => {
      throw new Error('KMS_UNAVAILABLE:SimulatedOutage');
    };
    let login503: number;
    try {
      const htu = `${baseUrl}/api/v1/auth/login`;
      const minted = await mintTestDpopProof({ method: 'POST', htu });
      const res = await http('POST', '/api/v1/auth/login', {
        body: { email: EMAIL, password: PASSWORD, organizationId: ORG_A },
        dpop: minted.proof,
      });
      login503 = res.status;
    } finally {
      accessKeys.signCompactJwt = originalSign;
    }

    // Bogus refresh → inactive (not a cross-tenant isolation proof; see earlier phases)
    const session = await login();
    const foreign = await http('POST', '/api/v1/auth/sessions/status', {
      body: { refreshToken: 'not-a-real-refresh-token-value-xxxxxxxxxxxx' },
    });
    const foreignActive = unwrapData<{ active?: boolean }>(foreign.json).active;

    // DPoP still required for refresh
    const noDpop = await http('POST', '/api/v1/auth/refresh', {
      body: { refreshToken: session.refreshToken },
    });

    rec(
      'DB-SEC-KMS-MK-FAILCLOSED',
      'No local fallback; login KMS outage 503; bogus refresh inactive; DPoP enforced',
      login503! === 503 && foreignActive === false && noDpop.status === 401,
      `login503=${login503} foreignActive=${foreignActive} noDpop=${noDpop.status}`,
      true,
    );
  });
});
