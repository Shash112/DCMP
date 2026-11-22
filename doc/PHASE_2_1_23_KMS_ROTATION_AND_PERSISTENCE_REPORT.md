# Phase 2.1.23 — KMS Persistence and Key Rotation Validation Report

## Decision readiness

**Persistence gap closed. Multi-key rotation code-path ready with doubles; live second-key AWS validation BLOCKED pending provisioning approval.**

Ready for next phase of non-prod hardening (not production cutover). No commit/push. No AWS mutations. No schema changes.

## Exact persistence issue and resolution

### Issue (from 2.1.22)

`refresh_idempotency_records.session_id` has a foreign key to `user_sessions`. The 2.1.22 envelope suite attempted a raw `INSERT` with a random `session_id` (no parent session). PostgreSQL rejected the insert; the suite caught the error and only validated in-memory encrypt/decrypt. That left **durable `encrypted_data_key` persistence unproven**.

### Intended relationship

- Login creates a `user_sessions` row (parent).
- Refresh rotation (`PostgresAuthStore.rotateRefresh`) consumes the presented token and `INSERT`s into `refresh_idempotency_records` with the **same** `organization_id` + `session_id`, including `encrypted_data_key` (KMS CiphertextBlob).
- Idempotent retry recovers via fingerprint lookup and envelope decrypt under tenant RLS.

### Resolution (no schema change)

1. Integration path `login → refresh` establishes a valid parent session, then asserts:
   - row present with non-null `encrypted_data_key`
   - `encryption_key_id` matches `kms-envelope:…`
   - decrypt recovers tokens
   - identical DPoP retry returns the same rotated refresh token
2. Encrypt-failure path: stub `cipher.encrypt` → **503** before `rotateRefresh`; idempotency row count unchanged (no partial persist; FK intact).
3. Soft allowlist on Decrypt `KeyId` using active master + `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS` (does not bypass CiphertextBlob CMK selection).

FK, RLS, and tenant isolation were **not** weakened.

## Files changed

| Path | Change |
|------|--------|
| `apps/backend/src/modules/auth/crypto/kms-refresh-envelope.provider.ts` | Post-Decrypt wrapping-key allowlist |
| `apps/backend/src/modules/auth/auth.service.ts` | Map refresh encrypt `KMS_UNAVAILABLE` → 503 before rotate |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.23-persistence-rotation.integration.spec.ts` | **NEW** live persist + allowlist suite |
| `apps/backend/src/modules/auth/__tests__/multi-key-rotation.unit.spec.ts` | **NEW** local ES256 rotation + config parse |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.22-live-kms.integration.spec.ts` | Clarify refresh verify-list semantics |
| `apps/backend/package.json` | `test:auth:kms:persist`; expand `test:auth:kms-unit` |
| `.env.example` | Documented KMS placeholders (required vs optional) |
| `doc/PHASE_2_1_23_MULTI_KEY_PROVISIONING_PLAN.md` | **NEW** — awaiting CreateKey approval |
| `doc/PHASE_2_1_23_KMS_ROTATION_AND_PERSISTENCE_REPORT.md` | **NEW** this report |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.23/`

## Tests

| Suite | Result |
|-------|--------|
| `npm run test:auth:kms-unit` | **10 PASSED** (DI, DER, multi-key doubles, config) |
| `npm run test:auth:kms:persist` | **4 PASSED** |
| `npm run test:auth:kms` (2.1.22 regression) | **6 PASSED** |
| `npm run test:auth:memory` | **12 PASSED** |
| `npm run test:auth:postgres` | **14 PASSED** |
| `npm run test:auth:access` | **16 PASSED** |
| `npm run test:auth:redis` | **16 PASSED** |

### Phase 2.1.23 case IDs

| Test ID | Status | Notes |
|---------|--------|-------|
| DB-SEC-KMS-PERSIST-01 | **PASSED** | FK session → `encrypted_data_key` INSERT + SELECT + decrypt + idempotent retry |
| DB-SEC-KMS-PERSIST-02 | **PASSED** | Encrypt fail → 503; no new idempotency row |
| DB-SEC-KMS-ROTATE-LIVE | **PASSED** (compat only) | Single live ECC; second live key **NOT_RUN** |
| DB-SEC-KMS-REFRESH-ALLOWLIST | **PASSED** | Active master Decrypt accepted by allowlist |

### Failed / blocked / not run

| Item | Status |
|------|--------|
| Live access-token verify with a **prior** ECC key | **NOT_RUN** — no second ECC key; see provisioning plan |
| Live SSA HMAC verify with a **prior** HMAC key | **NOT_RUN** — no second HMAC key |
| Live refresh decrypt under a **prior** CMK | **NOT_RUN** — no second refresh CMK / historical ciphertext |
| CreateKey / Disable / ScheduleKeyDeletion | **NOT_RUN** (forbidden this phase) |
| Schema migration | **NOT_RUN** (not required) |

## Rotation compatibility findings

| Mechanism | Behavior |
|-----------|----------|
| `DCMP_KMS_ACCESS_TOKEN_KEY_ID` | Active signing key only (`kms:Sign`) |
| `DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS` | Loaded into JWKS via `GetPublicKey`; accepted for verify |
| `DCMP_KMS_SSA_HMAC_KEY_ID` | Active `GenerateMac` |
| `DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS` | Tried after active in `VerifyMac` loop |
| `DCMP_KMS_REFRESH_MASTER_KEY_ID` | Sole `GenerateDataKey` target |
| `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS` | **Was unused for crypto selection** (Decrypt uses CiphertextBlob). **Now** soft-allowlists returned `KeyId` after Decrypt (active master always allowed). Empty list ⇒ only active master. |

### Why REFRESH_MASTER_VERIFY_KEY_IDS was “unused”

AWS `Decrypt` does not need the caller to pick the CMK: the wrapping key is embedded in `CiphertextBlob`. Listing prior CMK IDs does not change which key unwraps. The list is now used as a **retirement safety rail** so unexpected wrapping keys fail closed during rotation grace.

### Retirement / removal risks

- Removing a prior ECC from `VERIFY_KEY_IDS` (or retiring via `retireForTest` / clearing accept) immediately invalidates outstanding access tokens signed by that kid.
- Removing a prior HMAC from `SSA_HMAC_VERIFY_KEY_IDS` rejects assertions still signed with that key.
- Disabling/deleting a refresh CMK that still wraps stored `encrypted_data_key` rows makes those idempotency records permanently undecryptable (fail-closed). Prefer long grace + allowlist before disable.
- Never set `AUTH_ALLOW_LOCAL_KEYS` in live KMS environments.

## Remaining live AWS requirements

See `doc/PHASE_2_1_23_MULTI_KEY_PROVISIONING_PLAN.md`.

### Addendum (Phase 2.1.24)

Prior non-prod keys were provisioned outside this phase. Live multi-key rotation validation is reported in `doc/PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md`. Historical 2.1.23 results above are unchanged; the “Blocked — provisioning approval” gate below was the status **at 2.1.23 close**.

## Security implications

- Envelope durability under real session FK is proven; no FK bypass.
- Encrypt outage before rotate is fail-closed **503** with no partial idempotency write.
- Unexpected wrapping KeyId after Decrypt fails closed.
- Exclusive KMS DI unchanged; local providers absent in KMS mode.
- Placeholders only in `.env.example` (no real account/key material committed by this phase’s docs beyond prior evidence references).

## Next-phase readiness

| Gate | Status |
|------|--------|
| Envelope PG persistence | **Ready** |
| Encrypt failure atomicity | **Ready** |
| Multi-key app logic (doubles + config) | **Ready** |
| Live multi-key AWS proof | **Blocked** — provisioning approval |
| Production cutover | **Not ready** |

**Implementation is ready for the next non-prod phase after multi-key provisioning approval (or to proceed on single-key ops with documented rotation-grace limits).**
