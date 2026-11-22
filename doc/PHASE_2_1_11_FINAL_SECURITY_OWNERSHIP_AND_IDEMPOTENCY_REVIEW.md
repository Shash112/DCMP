# DCMP Phase 2.1.11 — Independent Security Correction & Database Implementation Readiness

> **SUPERSEDED IN PART BY PHASE 2.1.12.** Remaining gaps (durable refresh idempotency, org column grants, complete DEFINER RLS SQL, audit SELECT=`42501`, path-preserving verified digests) are resolved in [PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md](PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md). Do not use 2.1.11 “fail-closed after Redis cache loss,” trailing-slash stripping, or audit “0 rows” SELECT expectations as current baseline.

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Principal PostgreSQL 16 Security Engineer, Distributed Systems Architect, OAuth 2.0 / RFC 9449 Specialist & Independent Database Security Reviewer  
**Document Purpose:** Independent correction of SECURITY DEFINER ownership/EXECUTE semantics, organization lifecycle RLS separation, audit ingestion trust boundary, database-authoritative refresh serialization, cache-hit/logout consistency, complete RLS inventory, canonical retry-key encoding, ADR reconciliation, and expanded acceptance tests  
**Baseline Date:** November 22, 2026 (Phase 2.1.11 Corrected Specification Baseline)  
**Status:** **Superseded where contradictory — see Phase 2.1.12**  
**SQL executed against PostgreSQL 16:** **No**  
**Security tests implemented:** **No**  
**Security tests passed:** **No**

**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](PHASE_2_1_DATABASE_DESIGN_REVIEW.md) — authoritative design baseline (updated by this review)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md) — ADR register (reconciled by this review)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md) — prior proposed baseline (**superseded where contradictory**)

---

## 0. Independent Review Verdict

Phase 2.1.10 claimed “Approved Architectural & Security Baseline — Ready for Phase 2.2 Stage 1 Implementation.” Independent inspection of the SQL examples and ADR text shows **critical contradictions that remain unresolved in executable form**:

| Claim in prior docs                          | Independent finding                                                                                                                          |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| SECURITY DEFINER privileges “complete”       | `ALTER FUNCTION ... OWNER TO` missing; `verify_support_signature()` EXECUTE revoked from the role whose RLS policies call it                 |
| Org lifecycle policy correct                 | `FOR ALL ... USING (true) WITH CHECK (true)` grants unrestricted org-row access; conflates lifecycle admin with tenant business-data support |
| Audit writer “tamper-evident” / authenticity | `WITH CHECK (true)` + enum CHECKs do **not** authenticate actor, source, or event contents                                                   |
| Redis Redlock “guarantees” concurrency       | PostgreSQL conditional update is the only correctness barrier; Redis failure modes force fail-closed re-auth, not silent recovery            |
| “Zero stale-credential window” (ADR-019)     | Contradicts acknowledged in-flight HTTP transit window (ADR-021 / Phase 2.1.10 §6)                                                           |
| ADR register reconciled                      | Duplicate ADR-025/026/027 summary rows; stale function signatures in ADR-009; Phase 2.1.8 baseline references remain                         |
| Tests “exhaustive” / readiness               | DB-SEC-001..074 are **PLANNED** only; none executed                                                                                          |

**Implementation-readiness decision:**  
**NOT READY for Phase 2.2 Stage 1.** Specification completeness for the corrected items below is **Architecture specification complete (documentation)**. SQL syntax has been **reviewed against PostgreSQL 16 documentation**, not executed. Do not start Phase 2.2 until explicit human approval after these corrections are accepted.

---

## 1. Finding Matrix (Step 2)

| #      | Existing specification (Phase 2.1.10 / ADR)                                                                                                      | Why incorrect or incomplete                                                                                                                                                                                                   | Required correction                                                                                                                                                              | Primary sections  | Verification method                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------- |
| **F1** | Role created; functions `SECURITY DEFINER`; REVOKE/GRANT without OWNER TO; `verify_support_signature` EXECUTE revoked from `dcmp_platform_admin` | SECURITY DEFINER runs as **owner**, not creator. Policy expressions evaluate with **caller** privileges (PG 16 §5.8); without EXECUTE, RLS calling `verify_support_signature()` fails. Helpers lack ownership/EXECUTE matrix. | Explicit `ALTER FUNCTION ... OWNER TO dcmp_sec_definer`; revoke PUBLIC; grant EXECUTE to roles that invoke (including RLS callers); never grant membership/`SET ROLE` on definer | §2                | Catalog: `pg_proc.proowner`, `has_function_privilege`; attempt SET ROLE; RLS query without EXECUTE |
| **F2** | `platform_admin_org_lifecycle_permissive FOR ALL USING (true) WITH CHECK (true)`                                                                 | Unrestricted SELECT/UPDATE/DELETE on all org rows; no command split; reads as “unrestricted tenant access” even though business tables use support HMAC                                                                       | Command-scoped org lifecycle policies; separate support path for tenant business data; metadata vs lifecycle fields                                                              | §3                | Policy catalog + negative tests for business tables without SSA                                    |
| **F3** | `audit_writer_insert_permissive ... WITH CHECK (true)` + enum CHECKs                                                                             | Any holder of audit credentials can fabricate arbitrary rows; CHECKs only constrain enums; authenticity not proven                                                                                                            | Trusted ingestion model: server-generated fields, actor from session identity, fixed `event_source`, append-only, independent commit connection                                  | §4                | Spoof INSERT tests; rollback durability on separate connection                                     |
| **F4** | Redlock serializes refresh; “absolute” protection                                                                                                | Lock lease expiry, Redis failover, partitions, and post-commit cache-write failure leave Redis non-authoritative                                                                                                              | PostgreSQL conditional `UPDATE ... WHERE consumed_at IS NULL RETURNING` as sole correctness barrier; Redis optional wait/cache                                                   | §5                | Two-connection race with Redis killed mid-flight                                                   |
| **F5** | “Zero stale-credential window” vs “&lt;3ms in-flight”                                                                                            | Physical HTTP delivery is outside DB linearization; zero-window claim is false                                                                                                                                                | Document DB auth sequence, FOR SHARE vs logout FOR UPDATE, commit point, in-flight limitation                                                                                    | §6                | Concurrent logout during cache-hit response                                                        |
| **F6** | Partial policy examples only                                                                                                                     | Incomplete inventory; overlapping PERMISSIVE OR risks; FOR ALL not justified per table                                                                                                                                        | Full RLS inventory by table/role/command; justify FOR ALL                                                                                                                        | §7                | `pg_policies` vs inventory                                                                         |
| **F7** | Pipe-delimited `v1\|...` without escape/normalization rules                                                                                      | Field values containing `\|` or ambiguous UUID/hex/URI forms collide                                                                                                                                                          | Versioned length-prefixed canonical form + ≥5 test vectors                                                                                                                       | §8                | Hash equality vectors                                                                              |
| **F8** | Duplicate ADR rows; ADR-019 zero-window; ADR-009 old signatures; “approved” sign-off                                                             | Multiple authoritative truths                                                                                                                                                                                                 | Single ADR summary; revise ADR-009/012/016/019/021/022; supersede 2.1.10 approval language                                                                                       | §9 + ADR register | Grep for Approved/Ready/zero stale                                                                 |
| **F9** | 74 PLANNED tests; docs imply readiness                                                                                                           | Written cases ≠ executed                                                                                                                                                                                                      | Retain 001–074; add 075+; all accurately PLANNED until run                                                                                                                       | §10               | CI absence                                                                                         |

---

## 2. Finding 1 — SECURITY DEFINER Ownership & Execution Privileges

### 2.1 How PostgreSQL evaluates function permissions inside RLS

Per PostgreSQL 16 Row Security Policies:

1. Policy expressions run **as part of the query with the privileges of the user running the query**.
2. A `SECURITY DEFINER` function inside a policy still requires the **caller** to hold `EXECUTE` on that function.
3. Once invoked, the function body runs with the privileges of the **function owner** (not the original creator, if ownership was transferred).
4. With `FORCE ROW LEVEL SECURITY`, the definer role does **not** bypass RLS unless it also has `BYPASSRLS` (which DCMP forbids). The definer therefore needs its own permissive policies (or table privileges under policies) on tables it reads/writes.

**Consequence for Phase 2.1.10 §4.3:**  
`REVOKE ALL ON FUNCTION ... verify_support_signature() FROM dcmp_platform_admin` makes platform-admin RLS policies that call `verify_support_signature()` **non-functional** (permission denied / fail closed to 0 rows). That is not least-privilege hardening; it is a broken authorization path.

### 2.2 Corrected role

```sql
-- Dedicated routine owner: cannot log in, cannot escalate, cannot bypass RLS
CREATE ROLE dcmp_sec_definer
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOBYPASSRLS
  NOREPLICATION;

-- Runtime roles must NEVER be members of the definer role
REVOKE dcmp_sec_definer FROM dcmp_app;
REVOKE dcmp_sec_definer FROM dcmp_platform_admin;
REVOKE dcmp_sec_definer FROM dcmp_audit_writer;
-- Prefer explicit SET FALSE when creating any future membership grants:
-- GRANT dcmp_sec_definer TO <role> WITH SET FALSE INHERIT FALSE;  -- still avoid; do not grant at all
```

### 2.3 Corrected function ownership, PUBLIC revoke, and EXECUTE grants

```sql
-- After CREATE OR REPLACE FUNCTION ... SECURITY DEFINER SET search_path = pg_catalog, dcmp_security, public, pg_temp

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

-- Exact signatures required (PostgreSQL overloading)
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_decode(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_encode(BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.base64url_decode_jsonb(TEXT) FROM PUBLIC;

-- open_support_session: only platform-admin gateway DB role
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID)
  TO dcmp_platform_admin;

-- verify_support_signature: MUST be executable by every role whose RLS policies invoke it
GRANT EXECUTE ON FUNCTION dcmp_security.verify_support_signature()
  TO dcmp_platform_admin;

-- Helpers: callable only by definer-owned routines (SECURITY DEFINER owner always may execute own functions).
-- Do NOT grant helpers to dcmp_app / dcmp_platform_admin / dcmp_audit_writer.
-- If helpers are SECURITY INVOKER, keep EXECUTE revoked from PUBLIC and non-definer roles;
-- prefer SECURITY DEFINER helpers owned by dcmp_sec_definer with search_path pinned.
```

### 2.4 Table privileges for the definer (least privilege)

```sql
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_sec_definer;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_platform_admin; -- only for calling exposed functions

GRANT SELECT, INSERT, UPDATE ON dcmp_security.internal_keys TO dcmp_sec_definer;
GRANT SELECT, INSERT ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;
GRANT SELECT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_requests TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_grants TO dcmp_sec_definer;

-- Under FORCE RLS, definer needs permissive policies on those tables (SELECT/INSERT/UPDATE as required).
-- Do NOT grant dcmp_sec_definer SELECT on arbitrary tenant business tables.
```

### 2.5 Status of F1

| Item                            | Status                             |
| ------------------------------- | ---------------------------------- |
| Spec corrected in this document | **Yes**                            |
| SQL executed on PostgreSQL 16   | **No — UNRESOLVED at runtime**     |
| Proven via acceptance tests     | **No — PLANNED (DB-SEC-075..078)** |

---

## 3. Finding 2 — Organization Lifecycle Administration

### 3.1 Defect

```sql
-- Phase 2.1.10 (REJECTED as sole platform-admin org policy)
CREATE POLICY platform_admin_org_lifecycle_permissive ON public.organizations
  AS PERMISSIVE FOR ALL TO dcmp_platform_admin
  USING (true) WITH CHECK (true);
```

With no restrictive counterpart for lifecycle commands, this grants **unrestricted** SELECT/INSERT/UPDATE/DELETE on every organization row to `dcmp_platform_admin`. That is acceptable only if intentionally scoped to **org lifecycle metadata**, and must **not** be interpreted as authorizing tenant business-data access (users, inspections, etc.). Business-data access remains gated by `verify_support_signature()` on tenant-owned tables.

### 3.2 Operation separation

| Operation                                             | Role                  | Required auth                                             | RLS / privilege shape                                                                 |
| ----------------------------------------------------- | --------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Organization creation                                 | `dcmp_platform_admin` | Platform-admin auth at app layer                          | `FOR INSERT` permissive `WITH CHECK (true)` on `organizations` only                   |
| Organization metadata read (list/detail for SaaS ops) | `dcmp_platform_admin` | Platform-admin auth                                       | `FOR SELECT` permissive `USING (true)` on `organizations` only                        |
| Suspension / reactivation                             | `dcmp_platform_admin` | Platform-admin auth                                       | `FOR UPDATE` permissive; column-level app checks + trigger allow `status` changes     |
| Archival / soft-delete                                | `dcmp_platform_admin` | Platform-admin auth                                       | `FOR UPDATE` on `deleted_at` / status; hard `DELETE` denied or restricted to migrator |
| Customer profile read (own org)                       | `dcmp_app`            | Tenant context GUC                                        | SELECT + restrictive `id = current org`                                               |
| Customer profile non-lifecycle update                 | `dcmp_app`            | Tenant context                                            | UPDATE allowed except protected columns (trigger `42501`)                             |
| Customer business-data support access                 | `dcmp_platform_admin` | SSA + `open_support_session` + `verify_support_signature` | Tenant-owned table policies only — **not** implied by org lifecycle policies          |

### 3.3 Corrected organizations policies

```sql
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

-- Customer: own-org read
CREATE POLICY app_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_org_select_restrictive ON public.organizations
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- Customer: own-org non-lifecycle update (trigger still blocks status/org_code/id/deleted_at)
CREATE POLICY app_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_org_update_restrictive ON public.organizations
  AS RESTRICTIVE FOR UPDATE TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- Platform admin: lifecycle ONLY on organizations (command-scoped; NOT FOR ALL on tenant business tables)
CREATE POLICY platform_admin_org_insert_permissive ON public.organizations
  AS PERMISSIVE FOR INSERT TO dcmp_platform_admin WITH CHECK (true);

CREATE POLICY platform_admin_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);

CREATE POLICY platform_admin_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_platform_admin USING (true) WITH CHECK (true);

-- Hard DELETE: deny for runtime roles; soft-delete via UPDATE. Optional explicit deny:
-- no DELETE policy for dcmp_platform_admin => DELETE yields 0 rows under RLS.
REVOKE DELETE ON public.organizations FROM dcmp_app, dcmp_platform_admin;
```

**Justification for not using `FOR ALL` here:** lifecycle INSERT/SELECT/UPDATE have different threat models than DELETE; splitting commands prevents accidental DELETE privilege via a single OR-true permissive policy.

Tenant-owned business tables continue to use support HMAC permissive policies — **lifecycle org access does not open them**.

### 3.4 Status of F2

Specification corrected. Runtime proof **UNRESOLVED** (PLANNED DB-SEC-079..081).

---

## 4. Finding 3 — Audit Ingestion Trust Boundary

### 4.1 Defect

`WITH CHECK (true)` for `dcmp_audit_writer` allows any authenticated audit-writer session to insert **arbitrary** fabricated rows that satisfy CHECK enums. Database constraints do **not** prove event authenticity.

### 4.2 Trust model

| Concern                  | Rule                                                                                                                                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted event ingestion  | Only the Gateway Audit Publisher connects as `dcmp_audit_writer` on a dedicated pool; credentials never shared with `dcmp_app` / `dcmp_platform_admin`                            |
| Actor identity           | `actor_role` / `actor_id` must equal `session_user` / app-asserted admin id carried in a **server-built** payload; DB WITH CHECK binds `recorded_by = current_user`               |
| Event-source attribution | `event_source` fixed to `'GATEWAY'` for this role (or `'AUTH_SERVICE'` for that service’s role); callers cannot choose `'DATABASE_TRIGGER'`                                       |
| Tenant attribution       | Verified org UUID or `NULL` + `details.attempted_org_id`; never trust client-supplied org without gateway validation                                                              |
| Server-generated fields  | `id`, `created_at`, `recorded_by`, `ingest_txid` generated in DB defaults/triggers — not caller-controlled                                                                        |
| Spoofing protection      | RLS WITH CHECK + BEFORE INSERT trigger normalize/enforce server fields; app signs optional `integrity_hmac` over canonical event bytes (defense in depth; **not** sole guarantee) |
| Append-only              | No UPDATE/DELETE policies; REVOKE UPDATE/DELETE/TRUNCATE; BEFORE UPDATE/DELETE/TRUNCATE statement triggers raise `42501`                                                          |
| DBA / table-owner        | `FORCE RLS` binds owner DML; superuser/`BYPASSRLS` still can bypass — operational control required; not a PostgreSQL mathematical absolute                                        |
| Survive request rollback | Audit INSERT on **separate connection/transaction** that commits independently of the aborted support/auth transaction                                                            |

### 4.3 Corrected audit policies & trigger sketch

```sql
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON public.security_events FROM PUBLIC;
GRANT INSERT ON public.security_events TO dcmp_audit_writer;
GRANT SELECT ON public.security_events TO dcmp_app;              -- tenant-filtered
GRANT SELECT ON public.security_events TO dcmp_platform_admin; -- ops forensics
REVOKE UPDATE, DELETE, TRUNCATE ON public.security_events
  FROM dcmp_app, dcmp_platform_admin, dcmp_audit_writer;

-- Insert: bind recorder identity; constrain source for this role
CREATE POLICY audit_writer_insert_permissive ON public.security_events
  AS PERMISSIVE FOR INSERT TO dcmp_audit_writer
  WITH CHECK (
    recorded_by = CURRENT_USER
    AND event_source = 'GATEWAY'
    AND created_at IS NOT NULL
  );

-- Blind to writer
CREATE POLICY audit_writer_select_restrictive ON public.security_events
  AS RESTRICTIVE FOR SELECT TO dcmp_audit_writer
  USING (false);

-- Optional: no permissive SELECT for writer at all (default deny). If SELECT privilege
-- remains for error visibility, restrictive USING (false) still returns 0 rows.

CREATE POLICY app_audit_select_permissive ON public.security_events
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_audit_select_restrictive ON public.security_events
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (
    organization_id IS NOT NULL
    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
  );

CREATE OR REPLACE FUNCTION public.fn_security_events_before_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.id := COALESCE(NEW.id, gen_random_uuid());
  NEW.created_at := clock_timestamp();
  NEW.recorded_by := CURRENT_USER;
  -- Strip caller attempts to set privileged forensic fields inconsistently
  IF TG_OP = 'INSERT' AND CURRENT_USER = 'dcmp_audit_writer' THEN
    IF NEW.event_source IS DISTINCT FROM 'GATEWAY' THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: invalid event_source for audit writer'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- Dedicated TRUNCATE / UPDATE / DELETE statement triggers remain mandatory (Phase 2.1.10 §5.1).
```

**Honesty bound:** Compromised Gateway + `dcmp_audit_writer` credentials can still insert false Gateway-attributed events. Mitigations are credential isolation, network allowlists, optional HMAC with a key the writer role cannot read, and external log shipping. Do not claim database CHECKs prove authenticity.

### 4.4 Status of F3

Specification corrected. Authenticity under credential compromise **cannot be fully guaranteed by PostgreSQL alone** — residual risk documented. Tests PLANNED (DB-SEC-082..085).

---

## 5. Finding 4 — Database-Authoritative Refresh Serialization

### 5.1 Independent evaluation of Redis Redlock

| Failure mode                             | Redis-only outcome         | DCMP required outcome                                                                                          |
| ---------------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Lock lease expiration during rotation    | Second worker may proceed  | PG conditional update allows only one consumer of `T1`                                                         |
| Redis failover / partition               | Split-brain locks possible | Ignore lock as security boundary; PG serializes                                                                |
| Worker crash after lock acquire          | Lock expires; peer retries | Peer either cache-hits or hits consumed token                                                                  |
| PG commit then Redis cache-write failure | Cache empty                | Retry with `T1` → hard reuse → **fail closed** (re-auth). **No silent recovery promise**                       |
| Identical simultaneous requests          | Depends on lock            | One rotates; peer waits then cache-hits **if** cache write succeeded                                           |
| Different proofs, same consumed token    | Race                       | Second UPDATE returns 0 rows → revoke family                                                                   |
| Retry-cache TTL expiry                   | Miss                       | Nonce/JTI/token rules apply; may force re-auth                                                                 |
| Redis outage                             | Lock/cache unavailable     | Proceed with PG-only path or reject refresh if policy requires lock for DoS shaping — **correctness still PG** |

**Rule:** Redis may optimize waiting and response replay. Redis must **not** be the sole security guarantee.

### 5.2 Exact transaction sequence (concurrent identical proofs)

```
Time →

Client A (proof P, token T1)          Client B (proof P, token T1)           PostgreSQL                         Redis
------------------------------        ------------------------------        -------------------------------   -------------------------
1. Build RetryKey(P)                  1. Build RetryKey(P)
2. GET retry cache → MISS             2. GET retry cache → MISS
3. SET NX redlock:refresh:S           3. SET NX redlock → WAIT
   TTL=5000 owner=Ua
4. BEGIN READ COMMITTED
5. SELECT ... user_sessions
   WHERE id=S FOR SHARE
6. UPDATE user_session_tokens
   SET consumed_at=now(), ...
   WHERE id=T1 AND consumed_at IS NULL
   RETURNING id  → 1 row
7. INSERT new token T2
8. COMMIT  ◀── authoritative success
9. SETEX retry:RetryKey 30 enc(T2)    (B still waiting)
10. DEL redlock (Lua owner=Ua)
                                      11. acquires lock
                                      12. GET retry → HIT (if step 9 ok)
                                      13. BEGIN; SELECT is_active FOR SHARE
                                      14. COMMIT check
                                      15. return cached T2; release lock

If step 9 fails after step 8:
  B (or A retry) cache MISS → attempts UPDATE T1 → 0 rows → TOKEN_REUSE_DETECTED
  / fail-closed re-authentication. Successful “recovery” of T2 to the client is NOT guaranteed.
```

### 5.3 Status of F4

Specification corrected. Guaranteed client recovery after commit+cache-loss: **NOT promised**. Tests PLANNED (DB-SEC-048, 054, 071, 072, 086).

---

## 6. Finding 5 — Cache-Hit / Logout Consistency

### 6.1 Complete PostgreSQL cache-hit authorization sequence

```
1. Gateway receives refresh with DPoP proof P
2. Compute RetryKey(P); GET Redis retry cache
3. On HIT:
   a. BEGIN READ COMMITTED
   b. SELECT id, is_active FROM user_sessions
        WHERE id = :sessionId
        FOR SHARE          -- conflicts with logout's row lock
   c. If NOT FOUND OR is_active IS NOT TRUE → ROLLBACK; 401; purge cache
   d. COMMIT               -- authorization decision linearized here
   e. Decrypt cached credentials in app memory
   f. Write HTTP 200 response bytes to socket
4. Logout concurrent path:
   a. BEGIN
   b. UPDATE user_sessions SET is_active=false WHERE id=:sessionId
        -- takes RowExclusiveLock; waits if FOR SHARE held, or blocks share if first
   c. COMMIT               -- revocation linearized here
   d. SETEX tombstone; DEL retry keys
```

### 6.2 Distinctions (mandatory)

| Layer                  | What it guarantees                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------- |
| Database authorization | After step 3d, session was active at commit of the check transaction                |
| HTTP response delivery | **Not** covered by PostgreSQL. Bytes may already be on the wire when logout commits |
| Next request           | AuthGuard / refresh path must re-check DB (+ tombstone); revoked session fails      |

**Do not claim a zero stale-credential window.** The residual window is “credential already authorized and in-flight on the network,” bounded by RTT, not by DB locks. Phase 2.1.10’s “&lt;3ms” figure is an **assumption**, not a proof.

### 6.3 Status of F5

Specification corrected; ADR-019 zero-window language superseded. Tests PLANNED (DB-SEC-031, 055, 073, 087).

---

## 7. Finding 6 — Complete RLS Inventory

### 7.1 Legend

- **P** = AS PERMISSIVE; **R** = AS RESTRICTIVE
- **Force** = `FORCE ROW LEVEL SECURITY`
- **Support** = requires `verify_support_signature() = true` for `dcmp_platform_admin`
- Tenant GUC = `organization_id` (or org `id`) equals `app.current_organization_id`

### 7.2 Platform-global (9) — RLS not enabled

`platform_admins`, `platform_roles`, `platform_permissions`, `platform_admin_role_assignments`, `platform_role_permissions`, `permissions`, `license_plans`, `license_plan_entitlements`, `application_releases`  
Access via ordinary GRANT only (`dcmp_platform_admin` R/W as designed; `dcmp_app` SELECT on read-only subset). **No RLS policies.**

### 7.3 Tenant-root — `organizations`

| Role                  | SELECT | INSERT | UPDATE            | DELETE | Permissive     | Restrictive            | Tenant boundary           | Support        | Force |
| --------------------- | ------ | ------ | ----------------- | ------ | -------------- | ---------------------- | ------------------------- | -------------- | ----- |
| `dcmp_app`            | Y      | N      | Y (non-lifecycle) | N      | command-scoped | own `id`               | own org                   | N/A            | Y     |
| `dcmp_platform_admin` | Y      | Y      | Y (lifecycle)     | N      | command-scoped | none (lifecycle table) | SaaS ops on org rows only | N for org rows | Y     |
| `dcmp_audit_writer`   | N      | N      | N                 | N      | —              | —                      | —                         | —              | Y     |

### 7.4 Tenant-owned pattern (50 tables)

Tables: `organization_domains`, `organization_settings`, `users`, `user_sessions`, `user_session_tokens`, `roles`, `role_permissions`, `user_roles`, `locations`, `departments`, `teams`, `user_organizational_assignments`, `customer_licenses`, `license_events`, `assets`, `mobile_devices`, `device_user_sessions`, `checklist_categories`, `checklist_templates`, `checklist_versions`, `checklist_sections`, `checklist_questions`, `question_options`, `question_conditions`, `checklist_version_snapshots`, `checklist_schedules`, `checklist_assignments`, `assignment_targets`, `inspection_instances`, `inspection_responses`, `inspection_evidence`, `approval_records`, `inspection_history`, `issues`, `corrective_actions`, `corrective_action_history`, `sync_operations`, `sync_logs`, `notifications`, `notification_preferences`, `notification_delivery_logs`, `push_device_tokens`, `support_tickets`, `support_ticket_comments`, `support_diagnostics`, `support_access_requests`, `support_access_grants`, `support_access_logs`, `audit_logs`, `generated_files`.

| Role                  | SELECT | INSERT | UPDATE | DELETE | Permissive                                                                    | Restrictive                                           | Tenant boundary        | Support      | Force |
| --------------------- | ------ | ------ | ------ | ------ | ----------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------- | ------------ | ----- |
| `dcmp_app`            | Y      | Y      | Y      | Y      | `app_tenant_base_permissive` FOR ALL USING(true)/CHECK(true)                  | `app_tenant_isolation_restrictive` FOR ALL org match  | GUC org                | N            | Y     |
| `dcmp_platform_admin` | Y*     | Y*     | Y*     | Y*     | `platform_admin_support_permissive` FOR ALL gated by verify_support_signature | `platform_admin_tenant_restrictive` FOR ALL org match | support target org GUC | **Required** | Y     |
| `dcmp_audit_writer`   | N      | N      | N      | N      | —                                                                             | —                                                     | —                      | —            | Y     |

\*Only when support session open; otherwise 0 rows / fail closed.

**FOR ALL justification (tenant-owned):** Same boolean predicate applies to all commands; splitting would duplicate identical expressions without reducing privilege if GRANT already allows all four. Overlap risk: multiple permissive policies OR together — **do not** add a second permissive `USING (true)` for the same role.

### 7.5 Cross-cutting

| Table                       | Role                  | SELECT                 | INSERT                       | UPDATE | DELETE | Notes                                                                 | Force |
| --------------------------- | --------------------- | ---------------------- | ---------------------------- | ------ | ------ | --------------------------------------------------------------------- | ----- |
| `security_events`           | `dcmp_audit_writer`   | N (restrictive false)  | Y (CHECK recorded_by/source) | N      | N      | Append-only + triggers                                                | Y     |
| `security_events`           | `dcmp_app`            | Y + restrictive tenant | N                            | N      | N      | No global (`org IS NULL`) rows                                        | Y     |
| `security_events`           | `dcmp_platform_admin` | Y (ops)                | N                            | N      | N      | Separate permissive SELECT; no support required for security ops read | Y     |
| `platform_admin_audit_logs` | `dcmp_platform_admin` | Y                      | Y                            | N      | N      | Nullable org; app role no access                                      | Y     |
| `platform_admin_audit_logs` | `dcmp_app`            | N                      | N                            | N      | N      | —                                                                     | Y     |

### 7.6 Security schema tables

| Table                                       | Role               | Policies                                                                  | Force |
| ------------------------------------------- | ------------------ | ------------------------------------------------------------------------- | ----- |
| `dcmp_security.internal_keys`               | `dcmp_sec_definer` | permissive ALL                                                            | Y     |
| `dcmp_security.consumed_support_assertions` | `dcmp_sec_definer` | permissive INSERT/SELECT                                                  | Y     |
| `dcmp_security.support_session_challenges`  | `dcmp_sec_definer` | permissive SELECT/UPDATE (+ INSERT for challenge issuer role if separate) | Y     |

Runtime roles: **no** table privileges on `internal_keys`.

### 7.7 Overlapping permissive policy warning

Access = `(∨ permissive) ∧ (∧ restrictive)`. A single extra `USING (true)` permissive policy for the same role/command **opens all rows** unless restrictive policies still constrain. Inventory must ensure exactly one intentional permissive grant path per role/command class.

---

## 8. Finding 7 — Canonical Retry-Key Encoding (v1)

### 8.1 Ambiguity in Phase 2.1.10 pipe-delimited form

Concatenating fields with `|` without length prefixes allows collisions if any field can contain `|` or if UUID/hex casing differs.

### 8.2 Versioned canonical representation

**Encoding name:** `dcmp-retry-key-v1`  
**Hash:** SHA-256 over the canonical byte string  
**Output:** lowercase hex (64 chars), Redis key `auth:retry:` ‖ hex

**Canonical byte string (UTF-8):**

```
"dcmp-retry-key-v1\n"
+ "session_id=" + uuid_canon + "\n"
+ "token_hash=" + hex64_lower + "\n"
+ "proof_jti=" + uuid_canon + "\n"
+ "proof_nonce=" + nonce_exact + "\n"
+ "sig_hash=" + hex64_lower + "\n"
+ "htm=" + method_upper + "\n"
+ "htu=" + uri_canon + "\n"
```

**Rules:**

| Field         | Normalization                                                                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| UTF-8         | All labels and values encoded as UTF-8; no BOM                                                                                                        |
| UUID          | RFC 4122 lowercase hex with hyphens (`8-4-4-4-12`); reject non-canonical input before encode                                                          |
| Hex           | Lowercase `[0-9a-f]` only; token_hash/sig_hash exactly 64 chars                                                                                       |
| Field order   | Fixed order above; no optional fields                                                                                                                 |
| Delimiters    | LF (`\n`) separators; values **must not** contain LF (reject). No `                                                                                   | ` concatenation |
| URI (`htu`)   | Absolute URI; scheme/host lowercase; strip default ports; strip fragment; strip query; strip trailing `/` except path `/`; no unicode host — Punycode |
| Empty         | Forbidden for all fields → hard fail                                                                                                                  |
| Null          | Forbidden → hard fail                                                                                                                                 |
| `htm`         | Uppercase method tokens (`POST`)                                                                                                                      |
| `proof_nonce` | Exact server nonce string (case-sensitive); charset printable ASCII without LF                                                                        |

### 8.3 Test vectors (≥5)

Shared constants for vectors 1–4:

- `session_id` = `aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`
- `token_hash` = `00` × 32 → `0000…0000` (64 zeros)
- `proof_jti` = `ffffffff-0000-4000-8000-000000000001`
- `proof_nonce` = `nOnce-Exact-01`
- `sig_hash` = `11` × 32 → 64 ones hex
- `htm` = `POST`
- `htu` = `https://api.dcmp.com/api/v1/auth/refresh`

**Vector 1 — baseline**  
Canonical string as rules; digest = SHA-256(canonical UTF-8 bytes). Implementations must match bit-for-bit.

**Vector 2 — UUID case**  
Input session UUID with uppercase A–F must normalize to lowercase before hash. Hash **equals** Vector 1. Failing to normalize ⇒ false cache miss (availability bug) or fork.

**Vector 3 — URI trailing slash**  
`htu` input `https://api.dcmp.com/api/v1/auth/refresh/` → canonicalize by stripping trailing slash → **equals** Vector 1.

**Vector 4 — URI scheme case / default port**  
`https://API.DCMP.COM:443/api/v1/auth/refresh` → `https://api.dcmp.com/api/v1/auth/refresh` → **equals** Vector 1.

**Vector 5 — collision-prone pipe form (negative)**  
Legacy `v1|aaa...|0000...|...` must **not** be accepted by v1 encoder. Two distinct field sets that collide under naive pipe concatenation must produce **distinct** `dcmp-retry-key-v1` hashes. Example: reject any field containing `\n`; demonstrate that length-prefixed/line-based form does not equate `nonce="a"` + next field smuggling.

**Vector 6 — empty nonce (negative)**  
`proof_nonce=""` → encoding **rejected**; no Redis key issued.

_(Exact SHA-256 hex for Vector 1 is an implementation fixture to be generated in Phase 2.2 unit tests — not claimed “PASSED” here.)_

---

## 9. Finding 8 — ADR Reconciliation

### 9.1 Actions taken in the ADR register

1. Remove duplicate summary rows for ADR-025/026/027.
2. Revise **ADR-019**: replace “zero stale-credential window” with “DB-linearized check + acknowledged in-flight HTTP window.”
3. Revise **ADR-021**: audit `WITH CHECK` trust boundary; align revocation language with in-flight window.
4. Revise **ADR-009** / **ADR-016**: function signatures and EXECUTE-for-RLS requirement; mandatory `OWNER TO`.
5. Revise **ADR-012**: command-scoped org lifecycle ≠ business-data support.
6. Revise **ADR-022**: canonical encoding → `dcmp-retry-key-v1`.
7. Mark Phase 2.1.10 “approved / ready” language as **superseded** by this document.
8. Update baseline references from “Phase 2.1.8” to **Phase 2.1.11 corrected specification**.

### 9.2 Superseded guarantees (do not repeat)

- “Mathematically verified / production-ready / Phase 2.1 approved for 2.2” without executed tests
- “Zero stale-credential window”
- “Redlock guarantees absolute serialization” without PG conditional update
- “Audit CHECK constraints prove authenticity”
- `REVOKE EXECUTE` on `verify_support_signature` from platform admin

---

## 10. Finding 9 — Security Acceptance Test Catalog

All prior IDs **DB-SEC-001 through DB-SEC-074** retained with status **PLANNED**.  
New IDs covering Phase 2.1.11 findings:

| Test ID        | Finding | Scenario                                                       | Expected                                      | Status      |
| -------------- | ------- | -------------------------------------------------------------- | --------------------------------------------- | ----------- |
| **DB-SEC-075** | F1      | `proowner` of open/verify/helpers is `dcmp_sec_definer`        | Owner OID matches                             | **PLANNED** |
| **DB-SEC-076** | F1      | `dcmp_platform_admin` EXECUTE on `verify_support_signature()`  | `has_function_privilege = true`               | **PLANNED** |
| **DB-SEC-077** | F1      | PUBLIC lacks EXECUTE on security functions                     | Privilege false                               | **PLANNED** |
| **DB-SEC-078** | F1      | `dcmp_app` / admin `SET ROLE dcmp_sec_definer`                 | Error `42501`                                 | **PLANNED** |
| **DB-SEC-079** | F2      | Platform admin SELECT organizations without support session    | Allowed (lifecycle)                           | **PLANNED** |
| **DB-SEC-080** | F2      | Platform admin SELECT `users` without `open_support_session`   | 0 rows                                        | **PLANNED** |
| **DB-SEC-081** | F2      | Platform admin DELETE organization                             | Denied / 0 rows                               | **PLANNED** |
| **DB-SEC-082** | F3      | Audit writer INSERT with `event_source='ADMIN_PORTAL'`         | Reject `42501`/`23514`                        | **PLANNED** |
| **DB-SEC-083** | F3      | Audit writer INSERT with `recorded_by` spoof ≠ CURRENT_USER    | Reject                                        | **PLANNED** |
| **DB-SEC-084** | F3      | Support tx abort; audit on other connection                    | Audit row committed                           | **PLANNED** |
| **DB-SEC-085** | F3      | Audit writer SELECT                                            | 0 rows                                        | **PLANNED** |
| **DB-SEC-086** | F4      | Kill Redis after PG commit of rotation                         | Retry fails closed / re-auth; no duplicate T2 | **PLANNED** |
| **DB-SEC-087** | F5      | Logout commit during cache-hit HTTP write                      | Next request 401; no zero-window claim        | **PLANNED** |
| **DB-SEC-088** | F6      | Inventory vs `pg_policies` for all Force-RLS tables            | Exact match                                   | **PLANNED** |
| **DB-SEC-089** | F7      | Canonical vectors 1–4 identical hash                           | Match fixture                                 | **PLANNED** |
| **DB-SEC-090** | F7      | Empty nonce rejected                                           | No key                                        | **PLANNED** |
| **DB-SEC-091** | F1      | RLS policy query succeeds when EXECUTE granted                 | Rows visible under valid support sig          | **PLANNED** |
| **DB-SEC-092** | F1      | RLS policy query fails when EXECUTE revoked (negative harness) | Permission error or 0 rows per engine         | **PLANNED** |

**Classification rule:** A written test case is **PLANNED**. **IMPLEMENTED** only when automated harness exists. **PASSED** only after recorded execution against PostgreSQL 16 / staging.

---

## 11. Role & Privilege Matrix (Corrected Summary)

| Role                  | LOGIN   | BYPASSRLS | Owns SECURITY DEFINER fns    | Tenant business DML | Org lifecycle          | Audit INSERT    | Notes               |
| --------------------- | ------- | --------- | ---------------------------- | ------------------- | ---------------------- | --------------- | ------------------- |
| `dcmp_migrator`       | CI only | N + FORCE | Creates then transfers owner | Via migrations      | DDL                    | DDL             | Not runtime         |
| `dcmp_app`            | Y       | N         | N                            | RLS tenant          | Own-org limited UPDATE | N               |                     |
| `dcmp_platform_admin` | Y       | N         | N                            | Support HMAC only   | Y on `organizations`   | N               | EXECUTE verify+open |
| `dcmp_sec_definer`    | N       | N         | Y                            | N                   | N                      | N               | NOINHERIT           |
| `dcmp_audit_writer`   | Y       | N         | N                            | N                   | N                      | Y (constrained) | Blind SELECT        |
| `postgres`            | Y       | Y         | —                            | unrestricted        | unrestricted           | unrestricted    | Break-glass only    |

---

## 12. Remaining Risks & Assumptions

1. **SQL not executed** against PostgreSQL 16 in this phase.
2. **SSA key compromise** (Gateway or DB read of `internal_keys`) allows assertion forgery — acknowledged trust boundary.
3. **Audit writer credential compromise** allows Gateway-attributed false events.
4. **In-flight HTTP window** after DB authorization remains.
5. **Redis outage after commit** does not guarantee client receipt of `T2`.
6. **Superuser / BYPASSRLS operators** can bypass RLS and triggers if misused.
7. **Canonical hash fixtures** for retry keys await Phase 2.2 generation.
8. Context7 library docs were unavailable in this environment; corrections were checked against [PostgreSQL 16 Row Security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html) and GRANT/ALTER FUNCTION documentation.

---

## 13. Cross-Document Verification Notes

| Document                                         | Change                                                                          |
| ------------------------------------------------ | ------------------------------------------------------------------------------- |
| This file                                        | Created — authoritative correction report                                       |
| `PHASE_2_1_DATABASE_DESIGN_REVIEW.md`            | Status demoted; F1–F7 corrections folded into core decisions; baseline → 2.1.11 |
| `PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md` | Duplicates removed; ADR-009/012/016/019/021/022 revised; sign-off demoted       |
| `PHASE_2_1_10_...`                               | Add supersession banner only                                                    |

---

## 14. Explicit Implementation-Readiness Decision

| Gate                                                 | Result                                    |
| ---------------------------------------------------- | ----------------------------------------- |
| Architecture specification complete (corrected docs) | **YES — with residual risks listed**      |
| SQL syntax reviewed vs PostgreSQL 16 docs            | **YES**                                   |
| SQL executed against PostgreSQL 16                   | **NO**                                    |
| Security tests implemented                           | **NO**                                    |
| Security tests passed                                | **NO**                                    |
| Phase 2.1 approved for Phase 2.2                     | **NO — awaiting explicit human approval** |

**Stop.** Do not start Phase 2.2 implementation until approved.
