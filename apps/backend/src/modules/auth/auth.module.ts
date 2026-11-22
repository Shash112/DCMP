import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthAuditService } from './audit/auth-audit.service';
import { ACCESS_TOKEN_SIGNING_KEY_PROVIDER } from './crypto/access-token-key.provider';
import { LocalAccessTokenKeyProvider } from './crypto/local-access-token-key.provider';
import { KmsAccessTokenKeyProvider } from './crypto/kms-access-token-key.provider';
import { REFRESH_CIPHER_KEY_PROVIDER } from './crypto/key-provider.interface';
import { LocalTestKeyProvider } from './crypto/local-test-key.provider';
import { KmsRefreshEnvelopeProvider } from './crypto/kms-refresh-envelope.provider';
import { RefreshResponseCipher } from './crypto/refresh-response-cipher';
import {
  assertNoLocalCryptoInKmsMode,
  resolveAuthCryptoRegistration,
} from './crypto/auth-crypto.registration';
import {
  KmsSsaSigningProvider,
  LocalSsaSigningProvider,
  SSA_SIGNING_PROVIDER,
} from './crypto/ssa-signing.provider';
import { DpopBoundAuthGuard } from './guards/dpop-bound-auth.guard';
import { AUTH_STORE } from './persistence/auth-store.port';
import { MemoryAuthStore } from './persistence/memory-auth.store';
import { PostgresAuthStore } from './persistence/postgres-auth.store';
import { ValidationPgPool } from './persistence/pg.pool';
import { MemoryRedisAdapter } from './redis/memory-redis.adapter';
import { RealRedisAdapter } from './redis/real-redis.adapter';
import {
  AUTH_REDIS,
  AuthRedisPort,
  assertRedisDriverAllowed,
  resolveAuthRedisDriver,
} from './redis/redis.port';
import { SupportSessionController } from './support/support-session.controller';
import { SupportSessionService } from './support/support-session.service';

const usePostgres = process.env.AUTH_STORE_DRIVER === 'postgres';
const redisDriver = resolveAuthRedisDriver();
assertRedisDriverAllowed(redisDriver);
const useRealRedis = redisDriver === 'real';

const cryptoReg = resolveAuthCryptoRegistration();
assertNoLocalCryptoInKmsMode(cryptoReg);
const useKms = cryptoReg.useKms;

/**
 * AUTH_CRYPTO_DRIVER=kms → only KMS-backed crypto providers (no local key classes).
 * AUTH_CRYPTO_DRIVER=local → TEST-ONLY providers (refused in production).
 */
@Module({
  controllers: [AuthController, ...(usePostgres ? [SupportSessionController] : [])],
  providers: [
    AuthAuditService,
    ...cryptoReg.providerClasses,
    MemoryAuthStore,
    MemoryRedisAdapter,
    ...(useRealRedis ? [RealRedisAdapter] : []),
    DpopBoundAuthGuard,
    ...(usePostgres
      ? [
          ValidationPgPool,
          {
            provide: PostgresAuthStore,
            useFactory: (pg: ValidationPgPool) => new PostgresAuthStore(pg),
            inject: [ValidationPgPool],
          },
          SupportSessionService,
        ]
      : []),
    {
      provide: AUTH_STORE,
      useExisting: usePostgres ? PostgresAuthStore : MemoryAuthStore,
    },
    {
      provide: AUTH_REDIS,
      useExisting: useRealRedis ? RealRedisAdapter : MemoryRedisAdapter,
    },
    {
      provide: REFRESH_CIPHER_KEY_PROVIDER,
      useExisting: useKms ? KmsRefreshEnvelopeProvider : LocalTestKeyProvider,
    },
    {
      provide: ACCESS_TOKEN_SIGNING_KEY_PROVIDER,
      useExisting: useKms ? KmsAccessTokenKeyProvider : LocalAccessTokenKeyProvider,
    },
    {
      provide: SSA_SIGNING_PROVIDER,
      useExisting: useKms ? KmsSsaSigningProvider : LocalSsaSigningProvider,
    },
    {
      provide: RefreshResponseCipher,
      useFactory: (
        keys: LocalTestKeyProvider | KmsRefreshEnvelopeProvider,
        envelope?: KmsRefreshEnvelopeProvider,
      ) => new RefreshResponseCipher(keys, useKms ? envelope : undefined),
      inject: useKms
        ? [REFRESH_CIPHER_KEY_PROVIDER, KmsRefreshEnvelopeProvider]
        : [REFRESH_CIPHER_KEY_PROVIDER],
    },
    {
      provide: AuthService,
      useFactory: (
        store: MemoryAuthStore | PostgresAuthStore,
        redis: AuthRedisPort,
        cipher: RefreshResponseCipher,
        audit: AuthAuditService,
        accessKeys: LocalAccessTokenKeyProvider | KmsAccessTokenKeyProvider,
      ) => new AuthService(store, redis, cipher, audit, accessKeys),
      inject: [
        AUTH_STORE,
        AUTH_REDIS,
        RefreshResponseCipher,
        AuthAuditService,
        ACCESS_TOKEN_SIGNING_KEY_PROVIDER,
      ],
    },
  ],
  exports: [
    AuthService,
    AuthAuditService,
    AUTH_REDIS,
    MemoryRedisAdapter,
    ...(useRealRedis ? [RealRedisAdapter] : []),
    MemoryAuthStore,
    RefreshResponseCipher,
    DpopBoundAuthGuard,
    ACCESS_TOKEN_SIGNING_KEY_PROVIDER,
    SSA_SIGNING_PROVIDER,
    // Concrete crypto classes are NOT exported — inject via tokens only (Phase 2.1.25).
    // Local concrete exports retained for non-KMS test modules that resolve by class.
    ...(!useKms
      ? [LocalAccessTokenKeyProvider, LocalSsaSigningProvider, LocalTestKeyProvider]
      : []),
    ...(usePostgres ? [ValidationPgPool, PostgresAuthStore, SupportSessionService] : []),
  ],
})
export class AuthModule {}
