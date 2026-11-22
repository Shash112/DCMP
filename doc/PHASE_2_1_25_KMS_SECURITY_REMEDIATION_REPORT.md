# Phase 2.1.25 — KMS Test-Hook Hardening and Security Remediation Report

## Decision

**Remediation complete for findings F1–F9 from `doc/PHASE_2_1_24_SECURITY_REVIEW.md` (mandatory items).**  
Live non-prod multi-key suites remain green. No AWS mutations. No commit/push.

## Findings addressed

| ID    | Finding                                                              | Resolution                                                                          |
| ----- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| F1    | `setActiveHmacKeyIdForTest` unguarded                                | `assertCryptoTestHooksAllowed()` — allowed **only** when `NODE_ENV=test` (2.1.25.1) |
| F2    | `setActiveMasterKeyIdForTest` / `activeMasterKeyIdForTest` unguarded | Same fail-closed policy                                                             |
| F3    | `rotateForTest` / `retireForTest` on KMS access-token provider       | Same fail-closed policy + empty `newKeyId` check                                    |
| F4    | Concrete KMS providers exported from `AuthModule`                    | Removed from `exports`; inject via tokens only                                      |
| F5    | Test methods on production interface                                 | Removed `rotateForTest` / `retireForTest` from `AccessTokenSigningKeyProvider`      |
| F6    | Empty Decrypt `KeyId` skipped allowlist                              | Fail closed via `assertWrappingKeyAllowed`                                          |
| F7    | Loose `includes` / `endsWith` matching                               | Replaced with exact ARN equality or exact UUID (incl. UUID from ARN)                |
| F8–F9 | 2.1.24 tenant-isolation mislabel                                     | Report §7 corrected; FAILCLOSED test title/comments fixed                           |

Local `rotateForTest` / `retireForTest` on `LocalAccessTokenKeyProvider` and `LocalTestKeyProvider` use the same test-only gate.

## Files changed

| Path                                                                              | Change                                                       |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `apps/backend/src/modules/auth/crypto/crypto-test-hooks.ts`                       | **NEW** — production hard-block helper                       |
| `apps/backend/src/modules/auth/crypto/kms-wrapping-key-allowlist.ts`              | **NEW** — strict KeyId allowlist                             |
| `apps/backend/src/modules/auth/crypto/ssa-signing.provider.ts`                    | Guard on `setActiveHmacKeyIdForTest`                         |
| `apps/backend/src/modules/auth/crypto/kms-refresh-envelope.provider.ts`           | Guards + strict allowlist on Decrypt                         |
| `apps/backend/src/modules/auth/crypto/kms-access-token-key.provider.ts`           | Guards on rotate/retire                                      |
| `apps/backend/src/modules/auth/crypto/local-access-token-key.provider.ts`         | Guards on rotate/retire                                      |
| `apps/backend/src/modules/auth/crypto/local-test-key.provider.ts`                 | Guard on `rotateForTest`                                     |
| `apps/backend/src/modules/auth/crypto/access-token-key.provider.ts`               | Removed test methods from interface                          |
| `apps/backend/src/modules/auth/auth.module.ts`                                    | Stop exporting concrete KMS classes                          |
| `apps/backend/src/modules/auth/__tests__/crypto-test-hooks-and-allowlist.spec.ts` | **NEW** unit tests                                           |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.22-*.spec.ts`                  | Resolve envelope via `moduleRef.get(..., { strict: false })` |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.24-*.spec.ts`                  | Token DI + FAILCLOSED wording                                |
| `apps/backend/src/modules/auth/__tests__/multi-key-rotation.unit.spec.ts`         | Call concrete rotate/retire (no interface `!`)               |
| `apps/backend/package.json`                                                       | Include new unit file in `test:auth:kms-unit`                |
| `doc/PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md`                              | Correct §7 tenant wording                                    |
| `doc/PHASE_2_1_25_KMS_SECURITY_REMEDIATION_REPORT.md`                             | **NEW** this report                                          |

## Crypto test-hook guard behavior

### Phase 2.1.25 (initial)

Blocked only when `NODE_ENV=production`.

### Phase 2.1.25.1 (additional hardening)

Fail-closed: hooks allowed **only** when `NODE_ENV === 'test'`.

```typescript
if (process.env.NODE_ENV !== 'test') {
  throw new Error('Crypto test hooks are disabled outside test mode');
}
```

- Applies to every listed test-only mutation method.
- Blocked for `production`, `development`, `staging`, **undefined**, and any other value.
- **`DCMP_ALLOW_CRYPTO_TEST_HOOKS=true` does not override** (proven by unit tests).
- **`AUTH_ALLOW_LOCAL_KEYS=true` does not override**.
- `NODE_ENV=test` live AWS multi-key rotation drills continue to work.

## Dependency injection changes

- `AuthModule` exports `ACCESS_TOKEN_SIGNING_KEY_PROVIDER` and `SSA_SIGNING_PROVIDER` tokens (unchanged).
- Concrete `KmsAccessTokenKeyProvider`, `KmsSsaSigningProvider`, `KmsRefreshEnvelopeProvider` **no longer exported**.
- Providers remain registered for internal factories (`RefreshResponseCipher`, token `useExisting`).
- Local concrete class exports retained only when `!useKms` (test modules).
- KMS-only registration (no local classes) unchanged.

## Strict KeyId validation

- Empty / missing Decrypt `KeyId` → `KMS_UNAVAILABLE:UnexpectedWrappingKey` (plaintext zeroized when present).
- Allowed set = active refresh master + `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS`.
- Match rules: exact full-string equality **or** equal canonical UUIDs extracted from `…:key/<uuid>` ARNs.
- Substring / loose suffix / prefix matches **rejected**.

## New negative / guard tests

| Test                                                            | Result                |
| --------------------------------------------------------------- | --------------------- |
| Production hook block despite opt-in env vars                   | **PASSED**            |
| `NODE_ENV` undefined → blocked despite opt-in                   | **PASSED** (2.1.25.1) |
| `NODE_ENV=development` → blocked despite opt-in                 | **PASSED** (2.1.25.1) |
| `NODE_ENV=staging` → blocked despite opt-in                     | **PASSED** (2.1.25.1) |
| `NODE_ENV=test` → allowed                                       | **PASSED**            |
| Local rotate/retire blocked outside test                        | **PASSED**            |
| KMS SSA/envelope/access hooks blocked outside test              | **PASSED**            |
| Production KMS registration excludes local providers            | **PASSED**            |
| Empty KeyId fail closed                                         | **PASSED**            |
| Unexpected UUID rejected; ARN↔UUID exact OK; substring rejected | **PASSED**            |

## Exact test outcomes (after 2.1.25.1)

| Command                          | Outcome                 |
| -------------------------------- | ----------------------- |
| `npm run test:auth:kms-unit`     | **21 PASSED**           |
| `npm run test:auth:kms:multikey` | **4 PASSED** (live AWS) |
| `npm run test:auth:kms`          | **6 PASSED**            |
| `npm run test:auth:kms:persist`  | **4 PASSED**            |
| `npm run test:auth:memory`       | **12 PASSED**           |
| `npm run test:auth:postgres`     | **14 PASSED**           |
| `npm run test:auth:access`       | **16 PASSED**           |
| `npm run test:auth:redis`        | **16 PASSED**           |

**Failed:** none.

## Remaining risks

- Nest `app.get(ConcreteKmsClass)` from the same application root may still resolve a registered (non-exported) provider; **cross-module injection** without export is blocked. Residual in-process risk requires code that already holds the instance — hooks throw unless `NODE_ENV=test`.
- No live AWS negative Decrypt with a third unexpected CMK (unit allowlist covers the policy; IAM would also deny).
- Hardcoded active non-prod key UUID defaults in test harnesses remain (pre-existing; F10 deferred).
- Production cutover / retirement runbooks still out of scope.

## Confirmations

- **AWS resources untouched** — no CreateKey, Disable, ScheduleKeyDeletion, IAM, or key-policy changes.
- **No commit or push.**
- Unrelated dirty-tree files preserved.
- `farmerswing-prod` not used.

## Git diff review (2.1.25 / 2.1.25.1 scope)

Focused on crypto guards (test-only allowlist), allowlist module, AuthModule exports, unit/integration test adjustments, and documentation corrections listed above. No migration or production deployment config changes in this phase.

### 2.1.25.1 confirmation

- AWS resources untouched.
- No commit or push.
- Working tree otherwise preserved.
