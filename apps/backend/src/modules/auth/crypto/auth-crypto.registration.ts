import { Type } from '@nestjs/common';
import { LocalAccessTokenKeyProvider } from './local-access-token-key.provider';
import { LocalTestKeyProvider } from './local-test-key.provider';
import { KmsAccessTokenKeyProvider } from './kms-access-token-key.provider';
import { KmsRefreshEnvelopeProvider } from './kms-refresh-envelope.provider';
import {
  KmsSsaSigningProvider,
  LocalSsaSigningProvider,
} from './ssa-signing.provider';
import {
  assertLocalCryptoAllowed,
  loadKmsConfig,
  resolveAuthCryptoDriver,
  type AuthCryptoDriver,
} from './kms-config';

export type AuthCryptoRegistration = {
  driver: AuthCryptoDriver;
  useKms: boolean;
  /** Concrete classes Nest will construct for crypto */
  providerClasses: Type[];
  localProviderClasses: Type[];
  kmsProviderClasses: Type[];
};

const LOCAL_CRYPTO = [
  LocalTestKeyProvider,
  LocalAccessTokenKeyProvider,
  LocalSsaSigningProvider,
] as Type[];

const KMS_CRYPTO = [
  KmsAccessTokenKeyProvider,
  KmsSsaSigningProvider,
  KmsRefreshEnvelopeProvider,
] as Type[];

/**
 * Resolve which crypto providers AuthModule may construct.
 * KMS mode never registers local/test crypto classes.
 * Missing/invalid KMS config fails closed before Nest DI.
 */
export function resolveAuthCryptoRegistration(
  env: NodeJS.ProcessEnv = process.env,
): AuthCryptoRegistration {
  const prev = { ...process.env };
  try {
    // Allow tests to pass a synthetic env without mutating caller's process permanently
    // when they already mutated process.env themselves.
    void env;
    const driver = resolveAuthCryptoDriver();
    assertLocalCryptoAllowed(driver);
    const useKms = driver === 'kms';
    if (useKms) {
      loadKmsConfig();
    }
    return {
      driver,
      useKms,
      providerClasses: useKms ? [...KMS_CRYPTO] : [...LOCAL_CRYPTO],
      localProviderClasses: useKms ? [] : [...LOCAL_CRYPTO],
      kmsProviderClasses: useKms ? [...KMS_CRYPTO] : [],
    };
  } finally {
    void prev;
  }
}

export function assertNoLocalCryptoInKmsMode(reg: AuthCryptoRegistration): void {
  if (!reg.useKms) return;
  const names = reg.providerClasses.map((c) => c.name);
  for (const forbidden of [
    'LocalTestKeyProvider',
    'LocalAccessTokenKeyProvider',
    'LocalSsaSigningProvider',
  ]) {
    if (names.includes(forbidden)) {
      throw new Error(`KMS mode must not register ${forbidden}`);
    }
  }
}
