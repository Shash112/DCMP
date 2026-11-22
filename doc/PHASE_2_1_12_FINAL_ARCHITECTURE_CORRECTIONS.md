# DCMP Phase 2.1.12 — Final Architecture Corrections & Phase 2.2 Readiness Gate

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Principal PostgreSQL Database Architect, Application Security Engineer & SaaS Multi-Tenancy Specialist  
**Document Purpose:** Resolve remaining Phase 2.1.11 gaps — durable refresh idempotency, refresh test reconciliation, organization column grants, complete SECURITY DEFINER RLS SQL, audit-writer SELECT semantics, and verified canonical retry-key digests  
**Baseline Date:** November 22, 2026 (Phase 2.1.12 Specification Baseline)  
**Status:** **APPROVED FOR POSTGRESQL 16 VALIDATION** (documentation internally consistent)  
**Not:** Phase 2.2 implementation approval · Not runtime-proven · Not security-test-passed

| Validation gate                                    | Result                                                            |
| -------------------------------------------------- | ----------------------------------------------------------------- |
| SQL reviewed manually against PostgreSQL 16 docs   | **Yes**                                                           |
| SQL syntax validated by execution on PostgreSQL 16 | **No** (`psql` / Docker unavailable in this environment)          |
| Security tests implemented                         | **No**                                                            |
| Security tests executed and passed                 | **No**                                                            |
| SHA-256 vectors computed with real implementations | **Yes** (Python 3.13 `hashlib` + Node.js `crypto`, digests match) |

**Companion Artifacts:**

- [PHASE_2_1_DATABASE_DESIGN_REVIEW.md](PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [PHASE_2_1_11_FINAL_SECURITY_OWNERSHIP_AND_IDEMPOTENCY_REVIEW.md](PHASE_2_1_11_FINAL_SECURITY_OWNERSHIP_AND_IDEMPOTENCY_REVIEW.md) — superseded where contradictory
- [PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md) — superseded where contradictory

---

## 1. Executive Summary

Phase 2.1.11 correctly demoted false “production-ready” claims and fixed SECURITY DEFINER EXECUTE semantics, but left six specification gaps that would block honest PostgreSQL 16 validation:

| ID    | Gap                                                                      | Resolution in 2.1.12                                                                                                                                                |
| ----- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** | PG commit + Redis cache loss → legitimate retry fails closed             | **Option 1 selected:** durable `refresh_idempotency_records` (entity **#63**) stores AES-256-GCM ciphertext of the refresh response, keyed by canonical fingerprint |
| **B** | DB-SEC refresh scenarios contradict each other (both-200 vs fail-closed) | Scenario matrix rewritten for the Option 1 design                                                                                                                   |
| **C** | Platform-admin org UPDATE `USING/CHECK (true)` vs “lifecycle-only” prose | Column-level `GRANT UPDATE (...)` + trigger enforcement                                                                                                             |
| **D** | Incomplete SECURITY DEFINER dependency RLS SQL                           | Full SQL for keys, assertions, challenges, grants, requests                                                                                                         |
| **E** | Audit writer SELECT: privilege vs RLS zero-rows ambiguity                | **Design chosen:** no SELECT privilege → `42501` permission denied                                                                                                  |
| **F** | Trailing-slash stripping collapsed distinct routes; digests not computed | Path trailing slash **preserved**; five+ vectors with verified SHA-256                                                                                              |

**Entity baseline change:** 62 → **63** entities (add `refresh_idempotency_records`, Tenant-Owned, Stage 1, Organization & Identity domain). Eleven domains and seven migration stages unchanged.

**Final readiness decision:** **APPROVED FOR POSTGRESQL 16 VALIDATION** only. **NOT** approved to start Phase 2.2 implementation until validation evidence exists.

---

## 2. Correction A — Durable Refresh-Token Idempotency (Option 1 Selected)

### 2.1 Decision

| Option       | Summary                                      | Decision                           |
| ------------ | -------------------------------------------- | ---------------------------------- |
| **Option 1** | PostgreSQL-backed durable idempotency record | **Selected**                       |
| **Option 2** | Explicit reauthentication after cache loss   | Rejected as sole production design |

**Justification:** Phase 2.1.11’s fail-closed path made Redis a silent single point of legitimate-retry failure after a successful rotation. Mobile clients commonly retry identical DPoP proofs after timeouts. Storing a short-TTL, **application-encrypted** response blob in PostgreSQL (not plaintext tokens; ciphertext useless without the Gateway vault key) keeps PostgreSQL authoritative for both serialization and recovery, with Redis remaining an optimization only.

Option 2 remains documented only as the **post-TTL / post-revocation** outcome, not as the Redis-failure outcome.

### 2.2 New entity #63 — `refresh_idempotency_records`

| Property              | Value                              |
| --------------------- | ---------------------------------- |
| Prisma model (future) | `RefreshIdempotencyRecord`         |
| Domain                | Organization & Identity            |
| Scope                 | **Tenant-Owned**                   |
| Migration stage       | **Stage 1** (with sessions/tokens) |
| `organization_id`     | Mandatory                          |

```sql
CREATE TABLE public.refresh_idempotency_records (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         UUID NOT NULL,
  session_id              UUID NOT NULL,
  -- SHA-256 hex of dcmp-retry-key-v1 canonical bytes (64 lowercase hex chars)
  request_fingerprint     CHAR(64) NOT NULL,
  -- Token that was consumed to produce this result (hash only)
  presented_token_hash    CHAR(64) NOT NULL,
  -- Replacement token id created by this operation (no plaintext)
  issued_token_id         UUID NOT NULL,
  -- AES-256-GCM ciphertext of JSON { access_token, refresh_token, expires_in, token_type }
  -- Key NEVER stored in PostgreSQL; held in Gateway Vault/KMS only.
  response_ciphertext     BYTEA NOT NULL,
  response_iv             BYTEA NOT NULL,          -- 12-byte GCM nonce
  response_auth_tag       BYTEA NOT NULL,          -- 16-byte GCM tag
  encryption_key_id       TEXT NOT NULL,           -- Vault key version / kid
  dpop_jkt                TEXT NOT NULL,           -- must match user_sessions.dpop_jkt
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at              TIMESTAMPTZ NOT NULL,    -- created_at + 60 seconds
  invalidated_at          TIMESTAMPTZ NULL,        -- set on logout/revocation

  CONSTRAINT uq_refresh_idempo_fingerprint
    UNIQUE (organization_id, session_id, request_fingerprint),

  CONSTRAINT fk_refresh_idempo_session
    FOREIGN KEY (organization_id, session_id)
    REFERENCES public.user_sessions (organization_id, id)
    ON DELETE CASCADE,

  CONSTRAINT fk_refresh_idempo_issued_token
    FOREIGN KEY (organization_id, session_id, issued_token_id)
    REFERENCES public.user_session_tokens (organization_id, session_id, id)
    ON DELETE CASCADE,

  CONSTRAINT chk_refresh_idempo_fingerprint_hex
    CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  CONSTRAINT chk_refresh_idempo_token_hash_hex
    CHECK (presented_token_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT chk_refresh_idempo_iv_len
    CHECK (octet_length(response_iv) = 12),
  CONSTRAINT chk_refresh_idempo_tag_len
    CHECK (octet_length(response_auth_tag) = 16)
);

CREATE INDEX ix_refresh_idempo_expiry
  ON public.refresh_idempotency_records (expires_at)
  WHERE invalidated_at IS NULL;

CREATE UNIQUE INDEX uq_refresh_idempo_org_id
  ON public.refresh_idempotency_records (organization_id, id);
```

**Plaintext refresh/access tokens are never stored.** Only AES-256-GCM ciphertext decryptable by the Gateway.

### 2.3 Canonical request fingerprint

Identical to Correction F / `dcmp-retry-key-v1` SHA-256 hex (no `auth:retry:` Redis prefix in the DB column).

### 2.4 Proof and client binding

Before returning a recovered response, Gateway MUST verify:

1. DPoP signature validates for the presented proof.
2. Proof `jkt` equals `user_sessions.dpop_jkt` and row `dpop_jkt`.
3. `request_fingerprint` equals hash of the **current** request’s canonical form.
4. Session `is_active = true` (`SELECT ... FOR SHARE`).
5. `invalidated_at IS NULL` and `expires_at > clock_timestamp()`.

Mismatched fingerprint or proof → no recovery (treat as distinct request / reuse rules).

### 2.5 Encryption, AAD, and key management (Phase 2.1.13 Correction B)

| Item                  | Rule                                                                         |
| --------------------- | ---------------------------------------------------------------------------- |
| Algorithm             | AES-256-GCM                                                                  |
| Key location          | Gateway Vault/KMS only (`encryption_key_id` references version)              |
| DB roles              | Cannot decrypt; store opaque `BYTEA` only                                    |
| IV / nonce            | 96-bit (12-byte) CSPRNG per record; must be unique per key version           |
| Auth tag              | 128-bit GCM tag stored in `response_auth_tag`; verify before use             |
| Rotation              | New `encryption_key_id` for new rows; old rows expire ≤60s                   |
| Missing/revoked key   | Decryption fails closed → client must reauthenticate                         |
| Tamper / AAD mismatch | GCM authentication failure → treat as invalid recovery (no plaintext return) |

**Canonical AAD (UTF-8, LF-terminated fields, fixed order):**

```text
dcmp-refresh-aad-v1\n
organization_id=<uuid-canon>\n
session_id=<uuid-canon>\n
request_fingerprint=<64hex>\n
presented_token_hash=<64hex>\n
issued_token_id=<uuid-canon>\n
dpop_jkt=<exact>\n
encryption_key_id=<kid>\n
expires_at=<RFC3339 UTC with Z>\n
```

AAD is supplied to AES-GCM encrypt/decrypt and is **not** stored as a separate column (derivable from the row). Plaintext access/refresh tokens never enter PostgreSQL.

### 2.6 Expiry and cleanup

- Default TTL: **60 seconds** from `created_at` (covers mobile retry windows; longer than Redis 30s optional cache).
- Background job (BullMQ): `DELETE FROM refresh_idempotency_records WHERE expires_at < now() OR invalidated_at IS NOT NULL` in batches.
- Logout / family revocation: `UPDATE ... SET invalidated_at = clock_timestamp() WHERE session_id = :id`.

### 2.7 Transaction boundaries (authoritative sequence)

```
BEGIN;  -- READ COMMITTED, role dcmp_app, tenant GUC set
  -- 1. Optional: SELECT existing idempotency row FOR SHARE
  --    WHERE fingerprint = :fp AND invalidated_at IS NULL AND expires_at > now()
  --    If found → verify session active → COMMIT → decrypt in app → 200 (no new rotation)

  -- 2. SELECT user_sessions WHERE id=:sid FOR SHARE; require is_active

  -- 3. UPDATE user_session_tokens
  --      SET consumed_at = clock_timestamp(), replaced_by_token_id = :newId
  --      WHERE id = :oldId AND consumed_at IS NULL
  --      RETURNING id;
  --    0 rows → hard reuse path (see Correction B)

  -- 4. INSERT user_session_tokens (... new token hash ...)

  -- 5. INSERT refresh_idempotency_records (... ciphertext of response ...)
  --    ON CONFLICT (organization_id, session_id, request_fingerprint)
  --    DO NOTHING;  -- concurrent identical proof: re-SELECT winner's row
COMMIT;

-- 6. Best-effort Redis SETEX (non-authoritative)
-- 7. Return 200 with tokens
```

**Concurrent identical proofs:** One transaction wins the conditional token UPDATE + INSERT fingerprint. The loser gets unique-violation or 0-row consume, then **re-reads** the idempotency row by fingerprint and returns the same decrypted result → both may receive **200** with the **same** issued tokens (no second rotation).

**Different proofs, same T1:** Fingerprints differ. First consumes T1; second’s UPDATE returns 0 rows → **TOKEN_REUSE_DETECTED**, session family revoked, **401**, no idempotency return for the second fingerprint.

### 2.8 Logout / revocation

```sql
UPDATE public.refresh_idempotency_records
SET invalidated_at = clock_timestamp()
WHERE organization_id = :org
  AND session_id = :sid
  AND invalidated_at IS NULL;

UPDATE public.user_sessions
SET is_active = false, revoked_at = clock_timestamp()
WHERE organization_id = :org AND id = :sid;
```

Recovery after revocation must fail even if ciphertext row still exists.

### 2.9 Replay detection

| Case                                       | Behavior                                                     |
| ------------------------------------------ | ------------------------------------------------------------ |
| Identical proof within TTL, session active | Return stored result (200)                                   |
| Identical proof after TTL / invalidated    | No row → consumed token → hard reuse → revoke + 401 + reauth |
| Different proof, consumed token            | Hard reuse → revoke + 401                                    |
| Invalid DPoP                               | 401, **no** revoke                                           |

### 2.10 Privileges & RLS for `refresh_idempotency_records` (Phase 2.1.13 Correction A)

**Least privilege (supersedes broad `GRANT UPDATE`):**

```sql
ALTER TABLE public.refresh_idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_idempotency_records FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.refresh_idempotency_records FROM PUBLIC;
GRANT SELECT, INSERT ON public.refresh_idempotency_records TO dcmp_app;
GRANT UPDATE (invalidated_at) ON public.refresh_idempotency_records TO dcmp_app; -- only
GRANT SELECT, DELETE ON public.refresh_idempotency_records TO dcmp_cleanup;
-- DELETE restricted by RLS to expired OR invalidated rows
GRANT EXECUTE ON FUNCTION public.invalidate_refresh_idempotency(UUID, UUID) TO dcmp_app;

CREATE POLICY app_idempo_sel_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_idempo_ins_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR INSERT TO dcmp_app WITH CHECK (true);
CREATE POLICY app_idempo_upd_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_idempo_r ON public.refresh_idempotency_records
  AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

CREATE POLICY cleanup_idempo_del_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR DELETE TO dcmp_cleanup USING (true);
CREATE POLICY cleanup_idempo_r ON public.refresh_idempotency_records
  AS RESTRICTIVE FOR DELETE TO dcmp_cleanup
  USING (expires_at < clock_timestamp() OR invalidated_at IS NOT NULL);
```

**Immutability trigger** blocks changes to fingerprint, ciphertext, IV, tag, token refs, DPoP binding, and expiry even if privileges were mis-granted. Compromised app queries cannot replace ciphertext or rewrite fingerprints (DB-SEC-101).

### 2.11 Redis unavailable

| Phase                              | Behavior                                                                                                                                                                                                                    |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Before PG commit                   | Proceed without Redis lock/cache; PG conditional UPDATE + idempotency INSERT remain authoritative. Optional short advisory lock `pg_advisory_xact_lock(hashtext(session_id::text))` may replace Redlock when Redis is down. |
| After PG commit, Redis write fails | Idempotency row already committed → legitimate identical retry recovers via PostgreSQL                                                                                                                                      |
| Redis down on retry lookup         | Skip Redis; query PostgreSQL idempotency table                                                                                                                                                                              |

**Phase 2.1.11 claim “recovery not promised after Redis cache loss” is superseded** for identical-proof retries within TTL while the session remains active.

---

## 3. Correction B — Refresh Security Acceptance Matrix

Authoritative system for all rows: **PostgreSQL** (session state, token consume, idempotency record). Redis is non-authoritative.

| Scenario                                                   | HTTP                                                                           | New token issued? | Existing result returned?                      | Session/family revoked? | Reauth required?     | Notes                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------- | ---------------------------------------------- | ----------------------- | -------------------- | -------------------------------------------------- |
| **1. Simultaneous identical proof + same T1**              | Both **200**                                                                   | Once only         | Second returns same result via idempotency row | No                      | No                   | DB-SEC-071 revised                                 |
| **2. Simultaneous different valid proofs + same T1**       | First **200**, second **401** `TOKEN_REUSE_DETECTED`                           | First only        | No for second                                  | **Yes**                 | Yes for that session | DB-SEC-072                                         |
| **3. Retry after PG commit + Redis write OK**              | **200**                                                                        | No                | Yes (Redis then PG verify, or PG idempotency)  | No                      | No                   | DB-SEC-045                                         |
| **4. Retry after PG commit + Redis write fail**            | **200**                                                                        | No                | Yes (**PostgreSQL idempotency**)               | No                      | No                   | DB-SEC-048/054 revised — **no longer fail-closed** |
| **5. Retry after logout/revocation**                       | **401**                                                                        | No                | No (row invalidated / `is_active=false`)       | Already revoked         | Yes                  | DB-SEC-021/031/073                                 |
| **6. Reuse consumed T1 + valid proof, no idempotency hit** | **401**                                                                        | No                | No                                             | **Yes**                 | Yes                  | Outside TTL / different fingerprint                |
| **7. Invalid or missing DPoP**                             | **401**                                                                        | No                | No                                             | **No**                  | No (fix proof)       | DB-SEC-019                                         |
| **8a. Redis outage before PG commit**                      | **200** if rotation succeeds                                                   | Yes               | N/A                                            | No                      | No                   | PG-only path                                       |
| **8b. Redis outage after PG commit**                       | First may still **200** (response in memory); retry **200** via PG idempotency | No on retry       | Yes                                            | No                      | No                   | DB-SEC-086 revised                                 |

### 3.1 Catalogue amendments (status remains PLANNED)

| Test ID        | Amendment                                                                                                                               |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **DB-SEC-022** | Clarify: Redis outage with **already-consumed** token and **no** idempotency row → 401 revoke; with valid idempotency row → 200 recover |
| **DB-SEC-029** | Split into identical-proof vs unspecified; point to 071/072                                                                             |
| **DB-SEC-038** | Second request: if identical proof → recover; if different proof → 401 revoke; PG barrier prevents duplicate tokens                     |
| **DB-SEC-048** | Expected: **200** on identical retry via `refresh_idempotency_records` (not fail-closed)                                                |
| **DB-SEC-053** | After TTL expiry of idempotency row + Redis miss → 401 hard reuse                                                                       |
| **DB-SEC-054** | Align with 048: recover via PG if fingerprint matches and session active                                                                |
| **DB-SEC-071** | Both 200 **only** for identical proof; guaranteed by PG idempotency, not Redlock                                                        |
| **DB-SEC-086** | Redis kill after commit: identical retry **200** from PG                                                                                |
| **DB-SEC-093** | **NEW** — Concurrent identical proofs without Redis: both 200, one rotation                                                             |
| **DB-SEC-094** | **NEW** — Idempotency row invalidated on logout blocks recovery                                                                         |
| **DB-SEC-095** | **NEW** — Ciphertext present but wrong DPoP jkt → 401, no decrypt return                                                                |

All statuses: **PLANNED**.

---

## 4. Correction C — Organization Lifecycle Column Restrictions

### 4.1 Defect

`USING (true) WITH CHECK (true)` on UPDATE does not restrict columns. Documentation claimed “lifecycle-only.”

### 4.2 Column classification

Assume `organizations` columns (representative; exact Prisma columns locked at Stage 1 implementation):

| Class                                                    | Columns                                                                           | `dcmp_platform_admin` | `dcmp_app`                |
| -------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------- | ------------------------- |
| **Lifecycle (permitted for platform admin UPDATE)**      | `status`, `suspended_at`, `suspended_reason`, `deleted_at`, `updated_at`          | GRANT UPDATE          | Trigger blocks            |
| **Customer profile (app may UPDATE)**                    | `display_name`, `logo_url`, `timezone`, `locale`, `updated_at`                    | **No** column GRANT   | GRANT UPDATE              |
| **Identity / routing / security (immutable at runtime)** | `id`, `org_code`, `created_at`, `created_by`, `billing_account_id`, `data_region` | No UPDATE grant       | Trigger blocks + no grant |

### 4.3 Exact grants and RLS

```sql
-- Table owner: dcmp_migrator (FORCE RLS applies)
ALTER TABLE public.organizations OWNER TO dcmp_migrator;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.organizations FROM PUBLIC;
REVOKE ALL ON public.organizations FROM dcmp_app, dcmp_platform_admin;

GRANT SELECT ON public.organizations TO dcmp_app;
GRANT UPDATE (
  display_name, logo_url, timezone, locale, updated_at
) ON public.organizations TO dcmp_app;

GRANT SELECT, INSERT ON public.organizations TO dcmp_platform_admin;
GRANT UPDATE (
  status, suspended_at, suspended_reason, deleted_at, updated_at
) ON public.organizations TO dcmp_platform_admin;

REVOKE DELETE ON public.organizations FROM dcmp_app, dcmp_platform_admin;

-- RLS (permissive + restrictive)
CREATE POLICY app_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_org_select_restrictive ON public.organizations
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

CREATE POLICY app_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_org_update_restrictive ON public.organizations
  AS RESTRICTIVE FOR UPDATE TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

CREATE POLICY platform_admin_org_insert_permissive ON public.organizations
  AS PERMISSIVE FOR INSERT TO dcmp_platform_admin WITH CHECK (true);
CREATE POLICY platform_admin_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);
CREATE POLICY platform_admin_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_platform_admin
  USING (true) WITH CHECK (true);
-- No DELETE policy → DELETE denied under RLS even if privilege sneaks back
```

Column grants alone block `UPDATE organizations SET org_code = ...` for platform admin (`42501` insufficient privilege). Triggers add defense-in-depth:

```sql
CREATE OR REPLACE FUNCTION public.fn_organizations_lifecycle_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF CURRENT_USER = 'dcmp_app' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_code IS DISTINCT FROM OLD.org_code
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR NEW.suspended_at IS DISTINCT FROM OLD.suspended_at
       OR NEW.suspended_reason IS DISTINCT FROM OLD.suspended_reason
       OR NEW.billing_account_id IS DISTINCT FROM OLD.billing_account_id
       OR NEW.data_region IS DISTINCT FROM OLD.data_region
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: tenant cannot modify lifecycle/identity columns'
        USING ERRCODE = '42501';
    END IF;
  ELSIF CURRENT_USER = 'dcmp_platform_admin' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_code IS DISTINCT FROM OLD.org_code
       OR NEW.billing_account_id IS DISTINCT FROM OLD.billing_account_id
       OR NEW.data_region IS DISTINCT FROM OLD.data_region
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.logo_url IS DISTINCT FROM OLD.logo_url
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.locale IS DISTINCT FROM OLD.locale THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: platform admin limited to lifecycle columns'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_organizations_lifecycle_guard
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW
  EXECUTE FUNCTION public.fn_organizations_lifecycle_guard();
```

### 4.4 Tests (PLANNED)

| Test ID        | Expect                                                    |
| -------------- | --------------------------------------------------------- |
| **DB-SEC-096** | Platform admin `UPDATE status='SUSPENDED'` → success      |
| **DB-SEC-097** | Platform admin `UPDATE org_code=...` → `42501`            |
| **DB-SEC-098** | Platform admin `UPDATE display_name=...` → `42501`        |
| **DB-SEC-099** | `dcmp_app` `UPDATE status=...` → `42501`                  |
| **DB-SEC-100** | `dcmp_app` `UPDATE display_name=...` on own org → success |

---

## 5. Correction D — Complete SECURITY DEFINER Dependency RLS

### 5.1 Role and schema

```sql
CREATE ROLE dcmp_sec_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOBYPASSRLS NOREPLICATION;

CREATE SCHEMA dcmp_security AUTHORIZATION dcmp_sec_definer;
REVOKE ALL ON SCHEMA dcmp_security FROM PUBLIC;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_sec_definer;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_platform_admin; -- call functions only

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 5.2 `dcmp_security.internal_keys`

```sql
CREATE TABLE dcmp_security.internal_keys (
  key_id       TEXT PRIMARY KEY,
  key_secret   BYTEA NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
  valid_from   TIMESTAMPTZ NOT NULL,
  valid_until  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE dcmp_security.internal_keys OWNER TO dcmp_sec_definer;
ALTER TABLE dcmp_security.internal_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.internal_keys FORCE ROW LEVEL SECURITY;

REVOKE ALL ON dcmp_security.internal_keys FROM PUBLIC;
-- Only owner/definer; no grants to dcmp_app / dcmp_platform_admin / dcmp_audit_writer

CREATE POLICY sec_definer_internal_keys_all ON dcmp_security.internal_keys
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer
  USING (true) WITH CHECK (true);
```

Unauthorized direct access: missing privilege → `42501`.

### 5.3 `dcmp_security.consumed_support_assertions`

```sql
CREATE TABLE dcmp_security.consumed_support_assertions (
  jti          UUID PRIMARY KEY,
  admin_id     UUID NOT NULL,
  grant_id     UUID NOT NULL,
  consumed_at  TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL
);
ALTER TABLE dcmp_security.consumed_support_assertions OWNER TO dcmp_sec_definer;
ALTER TABLE dcmp_security.consumed_support_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.consumed_support_assertions FORCE ROW LEVEL SECURITY;

REVOKE ALL ON dcmp_security.consumed_support_assertions FROM PUBLIC;
GRANT SELECT, INSERT ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;

CREATE POLICY sec_definer_consumed_sel ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
CREATE POLICY sec_definer_consumed_ins ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR INSERT TO dcmp_sec_definer WITH CHECK (true);
```

### 5.4 `dcmp_security.support_session_challenges`

```sql
CREATE TABLE dcmp_security.support_session_challenges (
  challenge_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  platform_admin_id UUID NOT NULL,
  organization_id   UUID NOT NULL,
  grant_id          UUID NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at        TIMESTAMPTZ NOT NULL,
  consumed_at       TIMESTAMPTZ,
  transaction_xid   BIGINT,
  CONSTRAINT fk_challenges_grant
    FOREIGN KEY (grant_id) REFERENCES public.support_access_grants (id) ON DELETE CASCADE
);
ALTER TABLE dcmp_security.support_session_challenges OWNER TO dcmp_sec_definer;
ALTER TABLE dcmp_security.support_session_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.support_session_challenges FORCE ROW LEVEL SECURITY;

REVOKE ALL ON dcmp_security.support_session_challenges FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;

CREATE POLICY sec_definer_challenges_all ON dcmp_security.support_session_challenges
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer
  USING (true) WITH CHECK (true);

-- Challenge issuance: Gateway may insert via SECURITY DEFINER helper only (recommended),
-- not via direct table grants to dcmp_platform_admin.
```

### 5.5 Public support tables read by definer

```sql
-- support_access_grants / support_access_requests: owned by dcmp_migrator, FORCE RLS
GRANT SELECT ON public.support_access_grants TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_requests TO dcmp_sec_definer;

CREATE POLICY sec_definer_grants_select ON public.support_access_grants
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);

CREATE POLICY sec_definer_requests_select ON public.support_access_requests
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
```

Tenant policies for `dcmp_app` / support HMAC for `dcmp_platform_admin` remain as Phase 2.1.11 tenant-owned pattern; definer policies are **additional** permissive paths for the definer role only.

### 5.6 Functions — search_path, ownership, EXECUTE

```sql
-- All SECURITY DEFINER functions:
--   SET search_path = pg_catalog, dcmp_security, public, pg_temp
--   Fully qualify: dcmp_security.internal_keys, public.support_access_grants, etc.

ALTER FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID)
  OWNER TO dcmp_sec_definer;
ALTER FUNCTION dcmp_security.verify_support_signature()
  OWNER TO dcmp_sec_definer;
ALTER FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA)
  OWNER TO dcmp_sec_definer;
ALTER FUNCTION dcmp_security.base64url_decode(TEXT)
  OWNER TO dcmp_sec_definer;
ALTER FUNCTION dcmp_security.base64url_encode(BYTEA)
  OWNER TO dcmp_sec_definer;
ALTER FUNCTION dcmp_security.base64url_decode_jsonb(TEXT)
  OWNER TO dcmp_sec_definer;

REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_decode(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_encode(BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_decode_jsonb(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID)
  TO dcmp_platform_admin;
GRANT EXECUTE ON FUNCTION dcmp_security.verify_support_signature()
  TO dcmp_platform_admin;
-- Helpers: EXECUTE not granted to runtime roles (definer owner may call own functions)
```

### 5.7 Access matrix

| Object                        | Owner    | `dcmp_sec_definer` | `dcmp_platform_admin` direct table | Runtime other |
| ----------------------------- | -------- | ------------------ | ---------------------------------- | ------------- |
| `internal_keys`               | definer  | ALL via policy     | None → 42501                       | None          |
| `consumed_support_assertions` | definer  | SELECT/INSERT      | None                               | None          |
| `support_session_challenges`  | definer  | ALL                | None                               | None          |
| `support_access_grants`       | migrator | SELECT + policy    | Tenant/support RLS                 | app RLS       |
| `open_support_session`        | definer  | owner              | EXECUTE                            | No            |
| `verify_support_signature`    | definer  | owner              | EXECUTE (RLS)                      | No            |

No `BYPASSRLS` / superuser dependency.

---

## 6. Correction E — Audit-Writer Permissions (No SELECT Privilege)

### 6.1 Selected design

**No SELECT privilege** on `public.security_events` for `dcmp_audit_writer`.  
Direct `SELECT` → PostgreSQL **`42501 permission denied for table security_events`**, not “0 rows.”

RLS zero-row design is **rejected** for this role to avoid implying SELECT was intentionally granted.

### 6.2 SQL

```sql
ALTER TABLE public.security_events OWNER TO dcmp_migrator;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.security_events FROM PUBLIC;
REVOKE ALL ON public.security_events FROM dcmp_audit_writer;

GRANT INSERT ON public.security_events TO dcmp_audit_writer;
-- Explicitly no SELECT/UPDATE/DELETE/TRUNCATE

GRANT SELECT ON public.security_events TO dcmp_app;
GRANT SELECT ON public.security_events TO dcmp_platform_admin;

CREATE POLICY audit_writer_insert_permissive ON public.security_events
  AS PERMISSIVE FOR INSERT TO dcmp_audit_writer
  WITH CHECK (
    recorded_by = CURRENT_USER
    AND event_source = 'GATEWAY'
  );
-- No SELECT policy for dcmp_audit_writer (and no SELECT privilege)

CREATE POLICY app_audit_select_permissive ON public.security_events
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_audit_select_restrictive ON public.security_events
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (
    organization_id IS NOT NULL
    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
  );

CREATE POLICY platform_admin_audit_select_permissive ON public.security_events
  AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);

-- Append-only triggers (UPDATE/DELETE/TRUNCATE) remain as Phase 2.1.10/11
```

### 6.3 Trust boundary honesty

| Claim                                      | Valid?                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `recorded_by = CURRENT_USER` binds DB role | Yes (`dcmp_audit_writer`)                                                                                                 |
| `CURRENT_USER` proves human actor identity | **No** — only proves which DB role connected                                                                              |
| Human actor                                | Must be attributed in application-built payload fields (`actor_id`, etc.) with Gateway authentication; DB cannot prove it |
| Separate connection                        | Required so audit survives request rollback                                                                               |
| Table owner / superuser                    | Can bypass; operational control required                                                                                  |

### 6.4 Test alignment

| Test ID             | Expected (revised)                                             |
| ------------------- | -------------------------------------------------------------- |
| **DB-SEC-049**      | `SELECT` as `dcmp_audit_writer` → **ERROR 42501** (not 0 rows) |
| **DB-SEC-068**      | Same as 049 — **42501**                                        |
| **DB-SEC-067**      | INSERT success unchanged                                       |
| **DB-SEC-082..085** | Unchanged constrained insert / durability                      |

---

## 7. Correction F — Canonical Retry-Key `dcmp-retry-key-v1` (Revised)

### 7.1 Canonicalization rules

| Element                        | Rule                                                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Encoding                       | UTF-8, no BOM; reject non-UTF-8                                                                                   |
| Field order                    | Fixed: version banner, then `session_id`, `token_hash`, `proof_jti`, `proof_nonce`, `sig_hash`, `htm`, `htu`      |
| Delimiter                      | LF (`\n`) after every field including last; values must not contain LF                                            |
| `htm`                          | Uppercase HTTP method (`POST`)                                                                                    |
| URI scheme                     | Lowercase                                                                                                         |
| Hostname                       | Lowercase ASCII / Punycode; reject raw non-ASCII host                                                             |
| Port                           | Omit if default (`https`→443, `http`→80); keep non-default                                                        |
| **Path**                       | Preserve exact path including **trailing slash if present**. Empty path → `/`. **Do not strip trailing slashes.** |
| Query                          | Must be absent for refresh fingerprint; if present → reject encoding (refresh `htu` has no query)                 |
| Fragment                       | Strip (must not appear in DPoP `htu`)                                                                             |
| UUID                           | Lowercase RFC 4122 `8-4-4-4-12`                                                                                   |
| Hex (`token_hash`, `sig_hash`) | Lowercase `[0-9a-f]{64}`                                                                                          |
| `proof_jti`                    | UUID canonical form                                                                                               |
| `proof_nonce`                  | Exact case-sensitive server nonce; printable ASCII without LF                                                     |
| Empty / null                   | Reject entire encoding                                                                                            |

Serialized form:

```text
dcmp-retry-key-v1\n
session_id=<uuid>\n
token_hash=<64hex>\n
proof_jti=<uuid>\n
proof_nonce=<nonce>\n
sig_hash=<64hex>\n
htm=<METHOD>\n
htu=<absolute-uri>\n
```

`RetryKey` (Redis) = `auth:retry:` ‖ `SHA256(canonical_bytes).hexdigest()`  
DB fingerprint column = hex digest only.

### 7.2 Verified test vectors

Computed with **Python 3.13 `hashlib.sha256`** and cross-checked with **Node.js `crypto.createHash('sha256')`** (identical digests).

Shared field values unless noted:

- `session_id` = `aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`
- `token_hash` = 64 × `0`
- `proof_jti` = `ffffffff-0000-4000-8000-000000000001`
- `proof_nonce` = `nOnce-Exact-01`
- `sig_hash` = 64 × `1`
- `htm` = `POST`

#### Vector 1 — baseline path without trailing slash

**Canonical UTF-8 bytes (repr):**

```text
dcmp-retry-key-v1\nsession_id=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\ntoken_hash=0000000000000000000000000000000000000000000000000000000000000000\nproof_jti=ffffffff-0000-4000-8000-000000000001\nproof_nonce=nOnce-Exact-01\nsig_hash=1111111111111111111111111111111111111111111111111111111111111111\nhtm=POST\nhtu=https://api.dcmp.com/api/v1/auth/refresh\n
```

**SHA-256:** `4a3903dd8b4804fd6f0fa319ab36b55c5525fcc158502eccdd4fcff43d5c5e72`

#### Vector 2 — UUID uppercase input normalizes to Vector 1

Input `session_id=AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE` → canonical identical to Vector 1 → **same digest** `4a3903dd8b4804fd6f0fa319ab36b55c5525fcc158502eccdd4fcff43d5c5e72`

#### Vector 3 — path WITH trailing slash (DISTINCT)

**Canonical UTF-8 bytes (repr):**

```text
dcmp-retry-key-v1\nsession_id=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\ntoken_hash=0000000000000000000000000000000000000000000000000000000000000000\nproof_jti=ffffffff-0000-4000-8000-000000000001\nproof_nonce=nOnce-Exact-01\nsig_hash=1111111111111111111111111111111111111111111111111111111111111111\nhtm=POST\nhtu=https://api.dcmp.com/api/v1/auth/refresh/\n
```

**SHA-256:** `9f2f6f1587948051f54c870e3ce41cd3c642cb730172dee8b9cc055c85b7d7ca`

**Assert:** ≠ Vector 1 (trailing slash preserved; routes remain distinct).

#### Vector 4 — scheme/host case + default port `:443` omitted → Vector 1

Input `htu=https://API.DCMP.COM:443/api/v1/auth/refresh` normalizes to Vector 1 URI → digest `4a3903dd8b4804fd6f0fa319ab36b55c5525fcc158502eccdd4fcff43d5c5e72`

#### Vector 5 — semantically different path

`htu=https://api.dcmp.com/api/v1/auth/refresh2`

**SHA-256:** `f0789a6918a3250fb65ce4dc0c812a2b9f7d23849afa6eff60283e9845fc2d35`

#### Vector 6 — non-default port retained

`htu=https://api.dcmp.com:8443/api/v1/auth/refresh`

**SHA-256:** `640a0e471ee638eff64b3988072a5bbcdbf6c66bff079157dc2fc7753837645d`

#### Negative

- Empty `proof_nonce` → encoding rejected (no digest).
- `htu` with query string → rejected for refresh fingerprint.

---

## 8. Updated ADR Decisions (Phase 2.1.12)

| ADR                                       | Change                                                                                                                            |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **ADR-003**                               | Entity count **63**; four-tier counts: Tenant-Owned **51**                                                                        |
| **ADR-011 / ADR-019 / ADR-022 / ADR-027** | Durable PG idempotency supersedes “fail-closed after Redis cache loss” for identical proofs within TTL; Redlock non-authoritative |
| **ADR-012**                               | Column-level GRANT + trigger for lifecycle                                                                                        |
| **ADR-016**                               | Full dependency RLS SQL per §5                                                                                                    |
| **ADR-021 / ADR-024**                     | Audit writer: **no SELECT privilege**; SELECT → 42501                                                                             |
| **ADR-028**                               | **NEW** — PostgreSQL-backed refresh idempotency records                                                                           |
| **ADR-029**                               | **NEW** — Organization column-level privileges                                                                                    |
| **ADR-030**                               | **NEW** — Canonical retry-key path-preserving rules + verified digests                                                            |

---

## 9. PostgreSQL 16 Compatibility Review

| Topic                              | Assessment                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| `FORCE ROW LEVEL SECURITY`         | Valid PG 16                                                                      |
| `AS PERMISSIVE` / `AS RESTRICTIVE` | Valid                                                                            |
| `EXECUTE FUNCTION` in triggers     | PG 14+ synonym for `EXECUTE PROCEDURE`; valid in 16                              |
| `CHAR(64)` + CHECK regex           | Valid                                                                            |
| Column-level `GRANT UPDATE (cols)` | Valid                                                                            |
| `gen_random_uuid()`                | Requires `pgcrypto` or PG 13+ core — use `pgcrypto` extension as already planned |
| Advisory locks                     | Valid alternative when Redis down                                                |
| SQL executed here                  | **No** — `psql` and Docker not available                                         |

**Still required in next phase:** spin up disposable PostgreSQL 16; apply Stage 1 DDL+RLS in a scratch DB; run DB-SEC-071/072/048/054/086/093–100 and SEC DEFINER catalog checks.

---

## 10. Remaining Risks and Limitations

1. Gateway vault key compromise decrypts short-TTL idempotency ciphertexts.
2. In-flight HTTP window after authorization remains.
3. `CURRENT_USER` ≠ human actor.
4. Superuser/BYPASSRLS operational bypass.
5. Column list for `organizations` must match final Prisma schema at Stage 1.
6. No runtime proof until disposable PG 16 validation.
7. Ciphertext size / key rotation edge cases during deploy.

---

## 11. Global Consistency Actions

- Supersede Phase 2.1.11 §5.1/§5.2 “recovery not promised” for identical-proof+TTL case.
- Supersede Phase 2.1.11 §8 trailing-slash stripping.
- Supersede Phase 2.1.11 audit SELECT “0 rows” tests → 42501.
- Master design review entity count → 63.
- Remove Redlock-as-correctness claims wherever found in updated baselines.

---

## 12. Final Readiness Decision

| Decision                                                | Outcome |
| ------------------------------------------------------- | ------- |
| Documentation internally consistent for Corrections A–F | **Yes** |
| APPROVED FOR POSTGRESQL 16 VALIDATION                   | **Yes** |
| SQL executed on PostgreSQL 16                           | **No**  |
| Security tests passed                                   | **No**  |
| Approved to start Phase 2.2 implementation              | **No**  |

**Stop.** Proceed only to disposable PostgreSQL 16 validation after explicit approval. Do not start Phase 2.2 implementation in this phase.
