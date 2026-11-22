/**
 * Phase 2.1.23 — Multi-key rotation readiness with local doubles (no CreateKey).
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { SignJWT, importJWK, jwtVerify } from 'jose';
import { LocalAccessTokenKeyProvider } from '../crypto/local-access-token-key.provider';
import { loadKmsConfig } from '../crypto/kms-config';

function withEnv(overrides: Record<string, string | undefined>, fn: () => void): void {
  const keys = Object.keys(overrides);
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) {
    saved[k] = process.env[k];
    const v = overrides[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    fn();
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test('access-token rotation: new kid signs; old kid remains verifiable until retired', async () => {
  process.env.AUTH_ALLOW_LOCAL_KEYS = 'true';
  process.env.NODE_ENV = 'test';
  const keys = new LocalAccessTokenKeyProvider();
  const old = await keys.getActiveSigningKey();
  const oldKid = old.kid;
  assert.ok(old.privateKey);

  const now = Math.floor(Date.now() / 1000);
  const oldToken = await new SignJWT({ type: 'access', orgId: 'o', sid: 's', cnf: { jkt: 'j' } })
    .setProtectedHeader({ alg: 'ES256', kid: oldKid, typ: 'at+jwt' })
    .setIssuer('https://auth.dcmp.local')
    .setAudience('dcmp-api')
    .setSubject('u')
    .setJti('jti-old')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(old.privateKey!);

  const newKid = await keys.rotateForTest();
  assert.notEqual(newKid, oldKid);
  const active = await keys.getActiveSigningKey();
  assert.equal(active.kid, newKid);

  const jwks = await keys.listVerificationJwks();
  assert.ok(jwks.some((k) => k.kid === oldKid));
  assert.ok(jwks.some((k) => k.kid === newKid));

  const oldPub = await keys.getVerificationKey(oldKid);
  assert.ok(oldPub);
  const verified = await jwtVerify(oldToken, await importJWK(oldPub!.publicJwk, 'ES256'), {
    algorithms: ['ES256'],
    issuer: 'https://auth.dcmp.local',
    audience: 'dcmp-api',
  });
  assert.equal(verified.protectedHeader.kid, oldKid);

  await keys.retireForTest(oldKid);
  assert.equal(await keys.getVerificationKey(oldKid), null);
  const jwksAfter = await keys.listVerificationJwks();
  assert.ok(!jwksAfter.some((k) => k.kid === oldKid));
});

test('KMS config parses ACCESS_TOKEN and SSA HMAC verify key ID lists', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'kms',
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: 'active-ecc',
      DCMP_KMS_SSA_HMAC_KEY_ID: 'active-hmac',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: 'active-cmk',
      DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS: 'old-ecc-1, old-ecc-2',
      DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS: 'old-hmac-1',
      DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS: 'old-cmk-1',
      AWS_REGION: 'ap-south-1',
    },
    () => {
      const cfg = loadKmsConfig();
      assert.deepEqual(cfg.accessTokenVerifyKeyIds, ['old-ecc-1', 'old-ecc-2']);
      assert.deepEqual(cfg.ssaHmacVerifyKeyIds, ['old-hmac-1']);
      assert.deepEqual(cfg.refreshMasterVerifyKeyIds, ['old-cmk-1']);
    },
  );
});

test('REFRESH_MASTER_VERIFY_KEY_IDS purpose is documented as unwrap allowlist (not Sign)', () => {
  // Decrypt uses CiphertextBlob metadata to select the wrapping CMK.
  // VERIFY_KEY_IDS constrain which returned KeyIds are accepted after Decrypt
  // (rotation grace / retirement safety). They are not used for GenerateDataKey.
  withEnv(
    {
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: 'a',
      DCMP_KMS_SSA_HMAC_KEY_ID: 'b',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: 'c',
      DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS: 'prior-cmk',
    },
    () => {
      const cfg = loadKmsConfig();
      assert.ok(cfg.refreshMasterVerifyKeyIds.includes('prior-cmk'));
      assert.equal(cfg.refreshMasterKeyId, 'c');
    },
  );
});
