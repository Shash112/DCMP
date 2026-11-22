/**
 * Phase 2.1.25 / 2.1.25.1 — test-only crypto hooks + strict wrapping KeyId allowlist.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertCryptoTestHooksAllowed } from '../crypto/crypto-test-hooks';
import {
  assertWrappingKeyAllowed,
  extractKmsKeyUuid,
  isAllowedWrappingKeyId,
} from '../crypto/kms-wrapping-key-allowlist';
import { LocalAccessTokenKeyProvider } from '../crypto/local-access-token-key.provider';
import { LocalTestKeyProvider } from '../crypto/local-test-key.provider';
import { KmsAccessTokenKeyProvider } from '../crypto/kms-access-token-key.provider';
import { KmsRefreshEnvelopeProvider } from '../crypto/kms-refresh-envelope.provider';
import { KmsSsaSigningProvider } from '../crypto/ssa-signing.provider';
import { resolveAuthCryptoRegistration } from '../crypto/auth-crypto.registration';

const HOOK_DISABLED = /Crypto test hooks are disabled outside test mode/;

function withEnv(overrides: Record<string, string | undefined>, fn: () => void | Promise<void>) {
  const keys = Object.keys(overrides);
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) {
    saved[k] = process.env[k];
    const v = overrides[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return Promise.resolve()
    .then(() => fn())
    .finally(() => {
      for (const k of keys) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    });
}

test('assertCryptoTestHooksAllowed throws in production even with opt-in env vars', () => {
  return withEnv(
    {
      NODE_ENV: 'production',
      DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
      AUTH_ALLOW_LOCAL_KEYS: 'true',
    },
    () => {
      assert.throws(() => assertCryptoTestHooksAllowed(), HOOK_DISABLED);
    },
  );
});

test('assertCryptoTestHooksAllowed throws when NODE_ENV is undefined', () => {
  return withEnv(
    {
      NODE_ENV: undefined,
      DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
      AUTH_ALLOW_LOCAL_KEYS: 'true',
    },
    () => {
      assert.equal(process.env.NODE_ENV, undefined);
      assert.throws(() => assertCryptoTestHooksAllowed(), HOOK_DISABLED);
    },
  );
});

test('assertCryptoTestHooksAllowed throws when NODE_ENV=development', () => {
  return withEnv(
    {
      NODE_ENV: 'development',
      DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
      AUTH_ALLOW_LOCAL_KEYS: 'true',
    },
    () => {
      assert.throws(() => assertCryptoTestHooksAllowed(), HOOK_DISABLED);
    },
  );
});

test('assertCryptoTestHooksAllowed throws when NODE_ENV=staging', () => {
  return withEnv(
    {
      NODE_ENV: 'staging',
      DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
      AUTH_ALLOW_LOCAL_KEYS: 'true',
    },
    () => {
      assert.throws(() => assertCryptoTestHooksAllowed(), HOOK_DISABLED);
    },
  );
});

test('assertCryptoTestHooksAllowed allows NODE_ENV=test only', () => {
  return withEnv({ NODE_ENV: 'test', DCMP_ALLOW_CRYPTO_TEST_HOOKS: undefined }, () => {
    assert.doesNotThrow(() => assertCryptoTestHooksAllowed());
  });
});

test('LocalAccessTokenKeyProvider rotate/retire throw outside test despite AUTH_ALLOW_LOCAL_KEYS', async () => {
  await withEnv(
    {
      NODE_ENV: 'test',
      AUTH_ALLOW_LOCAL_KEYS: 'true',
    },
    async () => {
      const keys = new LocalAccessTokenKeyProvider();
      await withEnv(
        {
          NODE_ENV: 'production',
          AUTH_ALLOW_LOCAL_KEYS: 'true',
          DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
        },
        async () => {
          await assert.rejects(() => keys.rotateForTest(), HOOK_DISABLED);
          await assert.rejects(() => keys.retireForTest('access-es256:v0'), HOOK_DISABLED);
        },
      );
    },
  );
});

test('LocalTestKeyProvider.rotateForTest throws outside test mode', () => {
  return withEnv({ NODE_ENV: 'test', AUTH_ALLOW_LOCAL_KEYS: 'true' }, () => {
    const p = new LocalTestKeyProvider();
    return withEnv(
      {
        NODE_ENV: 'development',
        AUTH_ALLOW_LOCAL_KEYS: 'true',
        DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
      },
      () => {
        assert.throws(() => p.rotateForTest(), HOOK_DISABLED);
      },
    );
  });
});

test('KMS provider test hooks throw outside test mode', async () => {
  await withEnv(
    {
      NODE_ENV: 'test',
      AUTH_CRYPTO_DRIVER: 'kms',
      AUTH_ALLOW_LOCAL_KEYS: undefined,
      DCMP_KMS_ACCESS_TOKEN_KEY_ID: '802a81e6-3f7c-4a07-a15b-57b8ab506bfd',
      DCMP_KMS_SSA_HMAC_KEY_ID: '5a88e3e7-0732-466b-8df6-2c9885ddfdaa',
      DCMP_KMS_REFRESH_MASTER_KEY_ID: '8287866f-d8be-4c73-8372-aa24b78357d5',
      DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS: '38d7828b-ce36-4e1d-bba3-6c4b79de6223',
      AWS_REGION: 'ap-south-1',
      AWS_PROFILE: 'dcmp-nonprod',
    },
    async () => {
      const ssa = new KmsSsaSigningProvider();
      const envelope = new KmsRefreshEnvelopeProvider();
      let access: KmsAccessTokenKeyProvider | undefined;
      try {
        access = new KmsAccessTokenKeyProvider();
        await access.onModuleInit();
      } catch {
        access = undefined;
      }

      await withEnv(
        {
          NODE_ENV: 'staging',
          DCMP_ALLOW_CRYPTO_TEST_HOOKS: 'true',
          AUTH_ALLOW_LOCAL_KEYS: 'true',
        },
        async () => {
          assert.throws(() => ssa.setActiveHmacKeyIdForTest('anything'), HOOK_DISABLED);
          assert.throws(() => envelope.setActiveMasterKeyIdForTest('anything'), HOOK_DISABLED);
          assert.throws(() => envelope.activeMasterKeyIdForTest(), HOOK_DISABLED);
          if (access) {
            await assert.rejects(
              () => access!.rotateForTest('0ac837a0-293a-4e81-b280-5843761fea98'),
              HOOK_DISABLED,
            );
            await assert.rejects(
              () => access!.retireForTest('kms-es256:802a81e6-3f7c-4a07-a15b-57b8ab506bfd'),
              HOOK_DISABLED,
            );
          }
        },
      );
    },
  );
});

test('Production KMS registration does not include local providers', () => {
  return withEnv(
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
      const names = reg.providerClasses.map((c) => c.name);
      assert.ok(!names.includes('LocalAccessTokenKeyProvider'));
      assert.ok(!names.includes('LocalTestKeyProvider'));
      assert.ok(!names.includes('LocalSsaSigningProvider'));
    },
  );
});

test('wrapping KeyId allowlist: empty fails closed', () => {
  assert.equal(isAllowedWrappingKeyId('', ['a']), false);
  assert.throws(() => assertWrappingKeyAllowed('', ['a']), /UnexpectedWrappingKey/);
  assert.throws(() => assertWrappingKeyAllowed(undefined, ['a']), /UnexpectedWrappingKey/);
  assert.throws(() => assertWrappingKeyAllowed(null, ['a']), /UnexpectedWrappingKey/);
});

test('wrapping KeyId allowlist: exact UUID and ARN UUID match; reject substring', () => {
  const uuid = '38d7828b-ce36-4e1d-bba3-6c4b79de6223';
  const other = '8287866f-d8be-4c73-8372-aa24b78357d5';
  const arn = `arn:aws:kms:ap-south-1:980921756876:key/${uuid}`;
  assert.equal(extractKmsKeyUuid(uuid), uuid);
  assert.equal(extractKmsKeyUuid(arn), uuid);
  assert.equal(isAllowedWrappingKeyId(uuid, [uuid]), true);
  assert.equal(isAllowedWrappingKeyId(arn, [uuid]), true);
  assert.equal(isAllowedWrappingKeyId(uuid, [arn]), true);
  assert.equal(isAllowedWrappingKeyId(arn, [arn]), true);
  assert.equal(isAllowedWrappingKeyId(uuid, [other]), false);
  assert.equal(isAllowedWrappingKeyId(uuid, [uuid.slice(0, 8)]), false);
  assert.equal(isAllowedWrappingKeyId(`prefix-${uuid}`, [uuid]), false);
  assert.equal(isAllowedWrappingKeyId(uuid, [`${uuid}-extra`]), false);
  assert.throws(() => assertWrappingKeyAllowed(other, [uuid]), /UnexpectedWrappingKey/);
});
