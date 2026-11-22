# Phase 2.1.22 — Live AWS KMS Integration Report

## Decision readiness

**Non-production live KMS integration: READY for continued validation.**  
Not production readiness. No commit/push.

## Files changed

| Path                                                                                | Change                                                                    |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `apps/backend/src/modules/auth/crypto/auth-crypto.registration.ts`                  | **NEW** — exclusive local vs KMS provider registration                    |
| `apps/backend/src/modules/auth/auth.module.ts`                                      | Registers only `cryptoReg.providerClasses` (no local classes in KMS mode) |
| `apps/backend/src/modules/auth/__tests__/set-kms-redis-postgres-env.ts`             | **NEW** — live KMS env (no `AUTH_ALLOW_LOCAL_KEYS`)                       |
| `apps/backend/src/modules/auth/__tests__/auth-crypto-registration.spec.ts`          | **NEW** — DI/config unit tests                                            |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.22-live-kms.integration.spec.ts` | **NEW** — live KMS suite A–E                                              |
| `apps/backend/src/modules/auth/support/support-session.service.ts`                  | RESET SESSION AUTHORIZATION before grant confirm after attested open      |
| `apps/backend/package.json`                                                         | `test:auth:kms`, expanded `test:auth:kms-unit`                            |

## DI changes

- KMS mode constructs **only** `KmsAccessTokenKeyProvider`, `KmsSsaSigningProvider`, `KmsRefreshEnvelopeProvider`.
- Local providers are **not** registered in KMS mode → production KMS does **not** need `AUTH_ALLOW_LOCAL_KEYS`.
- Missing/duplicate KMS key IDs fail at `resolveAuthCryptoRegistration()` / `loadKmsConfig()`.
- Production + `AUTH_CRYPTO_DRIVER=local` still rejected.

## Environment variables used (live run)

```
AUTH_CRYPTO_DRIVER=kms
AWS_PROFILE=dcmp-nonprod
AWS_REGION=ap-south-1
DCMP_KMS_ACCESS_TOKEN_KEY_ID=802a81e6-3f7c-4a07-a15b-57b8ab506bfd
DCMP_KMS_SSA_HMAC_KEY_ID=5a88e3e7-0732-466b-8df6-2c9885ddfdaa
DCMP_KMS_REFRESH_MASTER_KEY_ID=8287866f-d8be-4c73-8372-aa24b78357d5
AUTH_REDIS_DRIVER=real
AUTH_REDIS_REQUIRED=true
AUTH_STORE_DRIVER=postgres
# AUTH_ALLOW_LOCAL_KEYS unset
```

AWS account gate: **980921756876** only.

## Database prerequisites (`dcmp_validation`)

| Prerequisite                       | Status                               |
| ---------------------------------- | ------------------------------------ |
| `encrypted_data_key` column        | Present                              |
| `open_support_session_attested`    | Present                              |
| SSA tables + `b64url_to_bytea`     | Present                              |
| Migrations auto-applied this phase | **No** (already present from 2.1.21) |

`dcmp_full_schema_validation` **not** used.

## Tests

| Suite                        | Result                  |
| ---------------------------- | ----------------------- |
| `npm run test:auth:kms-unit` | **7 PASSED** (DI + DER) |
| `npm run test:auth:kms`      | **6 PASSED / 0 FAILED** |

| Test ID                  | Result                                                   |
| ------------------------ | -------------------------------------------------------- |
| DB-SEC-KMS-AT-JWKS       | PASSED                                                   |
| DB-SEC-KMS-AT-SIGN       | PASSED (64-byte JOSE ES256)                              |
| DB-SEC-KMS-SSA-MAC       | PASSED (Mac + attested open + replay)                    |
| DB-SEC-KMS-ENVELOPE      | PASSED (round-trip + tamper/AAD deny)                    |
| DB-SEC-KMS-503           | PASSED (KMS Sign stub + Redis → 503; no local providers) |
| DB-SEC-KMS-ROTATE-COMPAT | PASSED                                                   |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.22/`

## AWS operations performed (read/crypto only)

- `sts:GetCallerIdentity`
- `kms:GetPublicKey`, `kms:Sign`
- `kms:GenerateMac`, `kms:VerifyMac`
- `kms:GenerateDataKey`, `kms:Decrypt`

**Not** performed: CreateKey, Disable, ScheduleKeyDeletion, IAM changes.

## Remaining gaps

1. `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS` still unused (Decrypt uses ciphertext metadata — document only).
2. Envelope PG persist under FK to sessions may skip INSERT when no session row (crypto round-trip still validated).
3. Full multi-key rotation against a second live ECC/HMAC key not exercised (single active keys).
4. `.env.example` still lacks KMS placeholder vars (optional follow-up; no secrets).
5. **Not production ready** — non-prod account only.

## Git

Branch `main`, dirty tree preserved. **No commit. No push.**
