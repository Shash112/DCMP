# Phase 2.1.24 — Live AWS KMS Multi-Key Rotation Validation Report

## 1. Executive summary and decision

**Live multi-key rotation validation: PASSED against non-prod AWS KMS.**

Application-level rotation grace works for:

- Access-token ECC (prior Sign → active switch → both verify + JWKS)
- SSA HMAC (prior GenerateMac → active switch → VerifyMac + attested open + replay deny)
- Refresh master CMK (persist envelope under prior → switch active → decrypt + idempotent retry → new encrypt under original → encrypt fail 503)

No keys were created, disabled, deleted, or policy-modified in this phase. No commit/push. Dirty working tree preserved. **Not** a production cutover decision.

## 2. AWS account and region (no credentials)

| Item | Value |
|------|-------|
| Account | `980921756876` |
| Region | `ap-south-1` |
| CLI profile | `dcmp-nonprod` |
| Identity | `arn:aws:iam::980921756876:user/dcmp-kms-dev` |
| FarmersWing / prod profile | **Not used** |

STS `GetCallerIdentity` gated the suite before any Nest bootstrap.

## 3. Key inventory

| Purpose | Role | Key ID |
|---------|------|--------|
| Access-token | Active (original) | `802a81e6-3f7c-4a07-a15b-57b8ab506bfd` |
| Access-token | Prior (v0) | `0ac837a0-293a-4e81-b280-5843761fea98` |
| SSA HMAC | Active (original) | `5a88e3e7-0732-466b-8df6-2c9885ddfdaa` |
| SSA HMAC | Prior (v0) | `1093c006-0546-469f-96d9-5619d4e44460` |
| Refresh master | Active (original) | `8287866f-d8be-4c73-8372-aa24b78357d5` |
| Refresh master | Prior (v0) | `38d7828b-ce36-4e1d-bba3-6c4b79de6223` |

Aliases (owner-provisioned): `alias/dcmp-nonprod-access-token-v0`, `alias/dcmp-nonprod-ssa-hmac-v0`, `alias/dcmp-nonprod-refresh-master-v0`.

Prior IDs were supplied to the test runner via environment variables only (`DCMP_KMS_*_PRIOR_KEY_ID`). They are **not** hardcoded in the multikey env harness source (active originals reuse the existing 2.1.22 harness defaults).

## 4. Access-token rotation results

| Case | Type | Result |
|------|------|--------|
| DB-SEC-KMS-MK-AT | **Live AWS** | **PASSED** |

Proven:

- Live `kms:Sign` with prior ECC via `rotateForTest(prior)`
- Switch active to original; prior remains verifiable
- Live Sign with original
- JWKS HTTP + provider list expose both kids
- Tampered signature rejected
- Unknown kid → `getVerificationKey` null
- `LocalAccessTokenKeyProvider` not registered in KMS mode

## 5. SSA HMAC rotation results

| Case | Type | Result |
|------|------|--------|
| DB-SEC-KMS-MK-SSA | **Live AWS** + PG SSA tables | **PASSED** |

Proven:

- Live `GenerateMac` under prior HMAC
- Switch active to original; prior assertion still verifies via `DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS`
- New mint uses original kid
- Invalid MAC → false
- Attested `openSession` with prior assertion succeeds
- Replay of same assertion/challenge denied
- Redis + PostgreSQL SSA path exercised (same support-session stack as 2.1.22)

## 6. Refresh master persisted-envelope rotation results

| Case | Type | Result |
|------|------|--------|
| DB-SEC-KMS-MK-REFRESH | **Live AWS** + **PostgreSQL** + HTTP/DPoP | **PASSED** |

Sequence executed:

1. Login/session (real auth flow, parent `user_sessions` FK)
2. Active refresh master temporarily set to **prior** CMK
3. Refresh persisted `encrypted_data_key`; `encryption_key_id` labeled with prior key
4. Active switched to **original**; prior retained in `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS`
5. Decrypt of persisted prior envelope succeeded (CiphertextBlob + allowlist)
6. Idempotent refresh retry returned the same rotated refresh token
7. Subsequent refresh encrypted under original master (`encryption_key_id` label)
8. Simulated encrypt failure → **503**, idempotency row count unchanged

No schema changes. FK/RLS/tenant path unchanged.

## 7. Fail-closed results (Phase 2.1.24)

| Case | Type | Result |
|------|------|--------|
| DB-SEC-KMS-MK-FAILCLOSED | Live app + injection | **PASSED** |

Phase 2.1.24 multi-key suite verified **fail-closed** behavior only:

- Local access-token / SSA providers absent in KMS mode
- KMS Sign outage on login → **503** (no local fallback)
- Bogus refresh token → `active=false`
- Refresh without DPoP → **401**

### Tenant isolation — not newly proven in 2.1.24

Phase 2.1.24 did **not** re-validate cross-tenant access, org-header spoofing, or RLS isolation. Those controls were established and regression-tested in earlier phases (notably `phase-2.1.20-redis-http.integration.spec.ts` `DB-SEC-ORG-HDR`, `postgres-auth.integration.spec.ts` cross-tenant session/GUC cases, and related access-token suites). Running `test:auth:redis` / `test:auth:postgres` / `test:auth:access` at 2.1.24 close confirmed those suites remained green; that is **regression**, not new 2.1.24 multi-key evidence.

Broader Redis-down / PG concurrency remain covered by those earlier suites (not re-injected in MK-FAILCLOSED).

## 8. Test commands and exact outcomes

Prior keys set in the shell only (example names; values as inventory above):

```powershell
$env:AWS_PROFILE='dcmp-nonprod'
$env:AWS_REGION='ap-south-1'
$env:DCMP_KMS_ACCESS_TOKEN_PRIOR_KEY_ID='…'
$env:DCMP_KMS_SSA_HMAC_PRIOR_KEY_ID='…'
$env:DCMP_KMS_REFRESH_MASTER_PRIOR_KEY_ID='…'
```

| Command | Classification | Outcome |
|---------|----------------|---------|
| `npm run test:auth:kms-unit` | Unit / doubles | **10 PASSED** |
| `npm run test:auth:kms:multikey` | **Live AWS** + PG + Redis | **4 PASSED** |
| `npm run test:auth:kms` | Live AWS regression (2.1.22) | **6 PASSED** |
| `npm run test:auth:kms:persist` | Live AWS + PG (2.1.23) | **4 PASSED** |
| `npm run test:auth:memory` | In-memory gateway | **12 PASSED** |
| `npm run test:auth:postgres` | PG integration | **14 PASSED** |
| `npm run test:auth:access` | PG access-token | **16 PASSED** |
| `npm run test:auth:redis` | Real Redis HTTP/DPoP/SSA | **16 PASSED** |

**Failed:** none  
**Blocked / not run:** none for required 2.1.24 scenarios  
Evidence: `infrastructure/database-validation/evidence/phase-2.1.24/` (no secrets/token plaintext)

## 9. Files changed (this phase)

| Path | Change |
|------|--------|
| `apps/backend/src/modules/auth/crypto/ssa-signing.provider.ts` | `setActiveHmacKeyIdForTest` for live rotation drills |
| `apps/backend/src/modules/auth/crypto/kms-refresh-envelope.provider.ts` | `setActiveMasterKeyIdForTest` / `activeMasterKeyIdForTest` |
| `apps/backend/src/modules/auth/__tests__/set-kms-multikey-env.ts` | **NEW** — multikey env (prior IDs from env only) |
| `apps/backend/src/modules/auth/__tests__/phase-2.1.24-live-multikey-rotation.integration.spec.ts` | **NEW** live suite |
| `apps/backend/package.json` | `test:auth:kms:multikey` |
| `doc/PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md` | **NEW** this report |
| `doc/PHASE_2_1_23_KMS_ROTATION_AND_PERSISTENCE_REPORT.md` | Addendum only (provisioning completed externally) |
| `doc/PHASE_2_1_23_MULTI_KEY_PROVISIONING_PLAN.md` | Addendum only |

## 10. Database changes

**None.** No migrations. No FK/RLS weakening. Used existing `dcmp_validation` + `encrypted_data_key` column.

## 11. Remaining gaps and production-readiness

| Gate | Status |
|------|--------|
| Live multi-key rotation (non-prod) | **Ready** |
| Automated CI with prior keys | Not wired (local env vars required) |
| Production KMS account / keys | **Not done** |
| Operational runbooks for key retirement | Still needed |
| Continuous rotation / alias cutover automation | Not in scope |
| Production cutover | **Not ready** |

Honest assessment: non-prod application rotation grace is validated end-to-end. Production readiness still requires prod account isolation, monitoring, retirement runbooks, and a formal go-live — outside 2.1.24.

## 12. Confirmations

- **No KMS keys deleted, disabled, or scheduled for deletion** in this phase.
- **No CreateKey** in this phase (keys were pre-provisioned by owner).
- **No key-policy or IAM policy changes** by this agent.
- **No commit or push** performed.
- **No plaintext DEKs, refresh tokens, access tokens, or AWS secrets** printed in this report.
- Working tree dirtiness preserved.

## AWS API classes exercised (application path)

- `kms:GetPublicKey`, `kms:Sign` (ECC active + prior)
- `kms:GenerateMac`, `kms:VerifyMac` (HMAC active + prior)
- `kms:GenerateDataKey`, `kms:Decrypt` (refresh prior wrap → original-active unwrap)
- `sts:GetCallerIdentity`
