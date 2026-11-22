/**
 * Phase 2.1.22 — DI / registration unit tests (no AWS calls when KMS IDs absent).
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertNoLocalCryptoInKmsMode,
  resolveAuthCryptoRegistration,
} from '../crypto/auth-crypto.registration';
import { assertLocalCryptoAllowed } from '../crypto/kms-config';

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

test('KMS mode does not register local crypto provider classes', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'kms',
      NODE_ENV: 'test',
      AUTH_ALLOW_LOCAL_KEYS: undefined,
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: '802a81e6-3f7c-4a07-a15b-57b8ab506bfd',
      DCMP_KMS_SSA_HMAC_KEY_ID: '5a88e3e7-0732-466b-8df6-2c9885ddfdaa',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: '8287866f-d8be-4c73-8372-aa24b78357d5',
      AWS_REGION: 'ap-south-1',
    },
    () => {
      const reg = resolveAuthCryptoRegistration();
      assert.equal(reg.useKms, true);
      assert.equal(reg.localProviderClasses.length, 0);
      assert.ok(reg.kmsProviderClasses.length === 3);
      assertNoLocalCryptoInKmsMode(reg);
      const names = reg.providerClasses.map((c) => c.name);
      assert.ok(!names.includes('LocalAccessTokenKeyProvider'));
      assert.ok(!names.includes('LocalTestKeyProvider'));
      assert.ok(!names.includes('LocalSsaSigningProvider'));
      assert.ok(names.includes('KmsAccessTokenKeyProvider'));
    },
  );
});

test('Production KMS registration succeeds without AUTH_ALLOW_LOCAL_KEYS', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'kms',
      NODE_ENV: 'production',
      AUTH_ALLOW_LOCAL_KEYS: undefined,
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: '802a81e6-3f7c-4a07-a15b-57b8ab506bfd',
      DCMP_KMS_SSA_HMAC_KEY_ID: '5a88e3e7-0732-466b-8df6-2c9885ddfdaa',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: '8287866f-d8be-4c73-8372-aa24b78357d5',
      AWS_REGION: 'ap-south-1',
    },
    () => {
      const reg = resolveAuthCryptoRegistration();
      assert.equal(reg.useKms, true);
      assert.equal(reg.localProviderClasses.length, 0);
    },
  );
});

test('Production local-key mode is rejected', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'local',
      NODE_ENV: 'production',
      AUTH_ALLOW_LOCAL_KEYS: undefined,
    },
    () => {
      assert.throws(() => assertLocalCryptoAllowed('local'), /Refusing local crypto/);
      assert.throws(() => resolveAuthCryptoRegistration(), /Refusing local crypto/);
    },
  );
});

test('Missing KMS configuration fails closed', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'kms',
      NODE_ENV: 'test',
      AUTH_ALLOW_LOCAL_KEYS: undefined,
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: undefined,
      DCMP_KMS_SSA_HMAC_KEY_ID: undefined,
      DCMP_KMS_REFRESH_MASTER_KEY_ID: undefined,
    },
    () => {
      assert.throws(() => resolveAuthCryptoRegistration(), /KMS mode requires/);
    },
  );
});

test('Duplicate KMS key IDs fail closed', () => {
  withEnv(
    {
      AUTH_CRYPTO_DRIVER: 'kms',
      NODE_ENV: 'test',
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: 'same-id',
      DCMP_KMS_SSA_HMAC_KEY_ID: 'same-id',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: 'other-id',
    },
    () => {
      assert.throws(() => resolveAuthCryptoRegistration(), /three distinct/);
    },
  );
});
