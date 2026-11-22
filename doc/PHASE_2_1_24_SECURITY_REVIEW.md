# Phase 2.1.24 — Independent Security Review and Final Acceptance

**Scope:** Phase 2.1.24 live multi-key KMS rotation implementation and uncommitted working-tree changes related to that phase.  
**Mode:** Inspection only. No code changes, no AWS changes, no commit/push.  
**Reviewer aids:** Manual inspection + [Security Review](d36ffd9f-30c0-437f-a4be-3c1d506bfd03) subagent on uncommitted changes.

---

## Recommendation

### REMEDIATION REQUIRED

Primary blocker: test-only active-key mutation methods are **callable on production KMS provider instances via Nest DI** with **no runtime environment guard**. There is no HTTP exposure today, but the hooks are not isolated from a production process.

Live multi-key crypto validation itself is strong. Acceptance should wait for the smallest safeguard remediation below (or an explicit owner waiver documenting the DI residual risk).

---

## 1. Findings and severity

| ID  | Severity   | Finding                                                                                                                                                                            | Location                                                          |
| --- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| F1  | **High**   | `setActiveHmacKeyIdForTest` mutates `ssaHmacKeyId` / kid with only empty-string check; no `NODE_ENV` / opt-in flag. Any code holding the provider can redirect live `GenerateMac`. | `ssa-signing.provider.ts:127-131`                                 |
| F2  | **High**   | `setActiveMasterKeyIdForTest` mutates `refreshMasterKeyId` with no runtime guard; redirects live `GenerateDataKey`.                                                                | `kms-refresh-envelope.provider.ts:52-55`                          |
| F3  | **High**   | `rotateForTest(newKeyId)` loads any IAM-reachable ECC key and sets it active for live `kms:Sign` without checking active/verify allowlists.                                        | `kms-access-token-key.provider.ts:154-158`                        |
| F4  | **High**   | `AuthModule` **exports** concrete `KmsAccessTokenKeyProvider`, `KmsSsaSigningProvider`, `KmsRefreshEnvelopeProvider`, enabling `app.get(ConcreteClass)` from importing modules.    | `auth.module.ts:129-131`                                          |
| F5  | **Medium** | `rotateForTest` / `retireForTest` appear on the production `AccessTokenSigningKeyProvider` interface as optional methods.                                                          | `access-token-key.provider.ts:32-35`                              |
| F6  | **Medium** | Refresh Decrypt KeyId allowlist is **skipped** when `out.KeyId` is empty (`if (returned) { … }`).                                                                                  | `kms-refresh-envelope.provider.ts:157-172`                        |
| F7  | **Medium** | Allowlist match uses loose `includes` / `endsWith` rules (substring risk vs strict ARN/UUID equality).                                                                             | `kms-refresh-envelope.provider.ts:160-166`                        |
| F8  | **Medium** | 2.1.24 case `DB-SEC-KMS-MK-FAILCLOSED` is labeled “tenant mismatch” but does **not** test cross-tenant / org-header spoof.                                                         | `phase-2.1.24-live-multikey-rotation.integration.spec.ts:543-579` |
| F9  | **Medium** | Phase report §7 overstates “tenant-isolation results” for 2.1.24; real isolation lives in earlier suites.                                                                          | `PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md` §7               |
| F10 | **Low**    | Active non-prod KMS UUIDs hardcoded as defaults in multikey env harness (same pattern as 2.1.22). Prior keys correctly env-only.                                                   | `set-kms-multikey-env.ts:21-26`                                   |
| F11 | **Low**    | Prior key UUIDs enumerated in 2.1.24 report (non-secret resource IDs).                                                                                                             | `PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md` §3               |
| F12 | **Info**   | No HTTP/admin route exposes test hooks. Config alone cannot invoke them.                                                                                                           | `auth.controller.ts`, support controllers                         |

---

## 2. Production runtime safety assessment (test-only key switching)

### Can `setActiveHmacKeyIdForTest` / `setActiveMasterKeyIdForTest` run in production?

| Vector                      | Result                                                                                                                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP API                    | **No** — no controller calls these methods.                                                                                                                                                                                                 |
| Env / config alone          | **No** — env sets bootstrap IDs and verify lists; does not call hooks.                                                                                                                                                                      |
| Nest DI on live process     | **Yes** — concrete providers are constructed in KMS mode, **exported**, and methods are public. A compromised or careless module can call them.                                                                                             |
| Explicit runtime safeguards | **None** beyond non-empty `keyId`. No `NODE_ENV === 'test'`, no `DCMP_ALLOW_CRYPTO_TEST_HOOKS`.                                                                                                                                             |
| Interface isolation         | **Partial** — SSA/refresh hooks are **not** on `SsaSigningProvider` / cipher interfaces (good). Access-token `rotateForTest` **is** on the production interface (weaker). Concrete class export bypasses interface isolation for all three. |

### Exploitability note

Remote unauthenticated attackers cannot call these hooks directly. Risk model is **in-process**: malicious dependency, debug admin code, or future module misuse. IAM still limits which KMS keys succeed, but the **application** can still switch among any permitted keys and expand JWKS via `rotateForTest` without config review.

### Proposed smallest safe correction (NOT implemented — awaiting approval)

1. At the start of `setActiveHmacKeyIdForTest`, `setActiveMasterKeyIdForTest`, `activeMasterKeyIdForTest`, and KMS `rotateForTest` / `retireForTest`:

   ```ts
   if (
     process.env.NODE_ENV === 'production' &&
     process.env.DCMP_ALLOW_CRYPTO_TEST_HOOKS !== 'true'
   ) {
     throw new Error('Crypto test hooks disabled in production');
   }
   ```

2. Stop exporting concrete KMS provider classes from `AuthModule` if nothing outside Auth needs them (keep token symbols only).

3. Optional follow-up (larger): move hooks off `AccessTokenSigningKeyProvider` into a test-only subclass / Nest test module override.

Do **not** implement until owner approves.

---

## 3. Tenant-isolation evidence classification

| Claim                                   | Proven in Phase 2.1.24 multi-key suite?   | Where actually proven                                                                                                                          |
| --------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Cross-tenant access rejection           | **No**                                    | `postgres-auth.integration.spec.ts` (session get under wrong org GUC); `phase-2.1.20-redis-http` / access suites with `ORG_B`                  |
| Org context from authenticated identity | **No** (not re-asserted)                  | Earlier gateway / access-token suites                                                                                                          |
| Client-supplied org ID spoofing         | **No**                                    | `DB-SEC-ORG-HDR` in `phase-2.1.20-redis-http.integration.spec.ts`; postgres “client organization header cannot authorize cross-tenant refresh” |
| PostgreSQL RLS enforcement              | **No** (not re-run as named 2.1.24 cases) | 2.1.19 / postgres store path + earlier DB validation                                                                                           |
| Refresh-token / session ownership       | **Partial**                               | 2.1.24 proves **session FK + idempotency ownership for ORG_A** under login→refresh; not cross-tenant ownership denial                          |
| Bogus refresh / DPoP / KMS 503          | **Yes**                                   | `DB-SEC-KMS-MK-FAILCLOSED` — fail-closed smoke only                                                                                            |

**Classification:** Phase 2.1.24 **must not** be cited as having validated tenant isolation. Report §7 should be treated as mislabeled; isolation remains an **earlier-phase** property, with regression suites (`test:auth:postgres`, `test:auth:redis`, `test:auth:access`) still green at 2.1.24 close.

---

## 4. Rotation safety assessment

| Control                                                      | Assessment                                                                                                                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unknown access-token kid rejected                            | **OK** — proven in 2.1.24 (`getVerificationKey` → null).                                                                                                           |
| Prior verify lists enforced for AT / SSA                     | **OK** — live prior Sign/MAC then verify after active switch with env `*_VERIFY_KEY_IDS`.                                                                          |
| Active key cannot be “forgotten” from verify by config alone | **OK at bootstrap** — active loaded separately; verify list is additive. **Caveat:** `retireForTest` / DI hooks can remove accept or switch active outside config. |
| Refresh Decrypt KeyId allowlist                              | **Present but incomplete** — happy path proven; empty KeyId skips check (F6); loose matching (F7); **no live negative** for `UnexpectedWrappingKey`.               |
| Decrypt/verify failure fail-closed                           | **OK** — invalid MAC false; bad JWT throws; encrypt/sign outage → 503; no local providers in KMS mode.                                                             |
| No plaintext key material logged                             | **OK** in reviewed KMS paths — errors log exception **names** only; DEK buffers zero-filled; evidence omits token/DEK plaintext.                                   |

---

## 5. Git diff assessment (Phase 2.1.24–relevant)

### Expected / in-scope

- `ssa-signing.provider.ts` — test hook
- `kms-refresh-envelope.provider.ts` — test hook + prior allowlist (from 2.1.23)
- `phase-2.1.24-live-multikey-rotation.integration.spec.ts`
- `set-kms-multikey-env.ts`
- `package.json` — `test:auth:kms:multikey`
- Docs: `PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md`, 2.1.23 addenda
- Evidence under `infrastructure/database-validation/evidence/phase-2.1.24/`

### Not observed in 2.1.24 delta

- Debug `console.log` of secrets
- AWS access keys / secret keys
- Database migration edits for this phase
- Production deployment config flips

### Residual hygiene

- Hardcoded **active** non-prod key UUID defaults in test env harnesses (pre-existing 2.1.22 pattern; F10).
- Working tree also contains large unrelated Phase 2.1.* auth/infra uncommitted work; this review does **not** re-certify all of that surface—only 2.1.24-touched security-relevant pieces above.

### Confirmations

- No commit or push performed for this review.
- Uncommitted work preserved.
- No AWS resource modifications.

---

## 6. Required remediation (before ACCEPT)

1. **Must:** Guard all crypto `*ForTest` / KMS `rotateForTest` / `retireForTest` hooks against production runtime (F1–F3), ideally plus stop exporting concrete KMS classes (F4).
2. **Should:** Fail closed when Decrypt returns empty KeyId; tighten allowlist matching; add negative UnexpectedWrappingKey test (F6–F7).
3. **Should:** Correct 2.1.24 report §7 / FAILCLOSED test name so tenant isolation is not claimed without evidence (F8–F9).

Smallest path to acceptance: item **1** only, with items 2–3 tracked as documented limitations if deferred.

---

## 7. What remains solid

- Live multi-key AWS validation for AT, SSA, and persisted refresh envelopes is real and meaningful.
- No HTTP key-rotation surface.
- KMS-only DI (no local crypto fallback) asserted in the live suite.
- Envelope persistence under session FK + encrypt-fail atomicity remain sound.
- No plaintext DEK/token leakage found in reviewed logs/evidence.

---

## Final decision

**REMEDIATION REQUIRED** — specifically for unguarded, DI-reachable test key-switching hooks on production provider classes (F1–F4).

Awaiting owner approval before implementing the smallest safeguard correction.
