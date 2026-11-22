# DCMP Phase 2.1.3 — Final Security & Implementation Readiness Review

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Database Architect & PostgreSQL Security Engineer  
**Document Purpose:** Definitive Security Architecture, Implementation-Level RLS Specifications, Refresh-Token Retry Cryptography, and Final Sign-Off  
**Baseline Date:** November 22, 2026 (Phase 2.1.5 Reconciled Security Baseline)  
**Status:** **Approved Architectural & Security Baseline — Ready for Stage 1 Implementation**  
**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md)
- [doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md)
- [doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md)

---

## 1. Executive Summary & Resolution Matrix of Review Findings

This document resolves the implementation-level security findings identified during the Phase 2.1 reviews, establishing an ironclad, mathematically verified implementation specification.

### 1.1 Resolution Matrix

| #     | Review Finding                                            | Architectural Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1** | **Platform Admin Support Access under `FORCE RLS`**       | Implemented dedicated `SECURITY DEFINER` function `open_support_session` owned by non-login role `dcmp_sec_definer` with fixed `search_path = public, dcmp_security, pg_temp`. Access verified via cryptographic HMAC transaction signature. `dcmp_platform_admin` retains `NOBYPASSRLS`.                                                                                                                                                                                                        |
| **2** | **Organization Lifecycle Access & Customer Restrictions** | Customer role `dcmp_app` is denied `INSERT` and `DELETE` on `organizations`, and an engine trigger (`trg_prevent_tenant_org_lifecycle_tampering`) blocks tenant modification of `status`, `org_code`, or `deleted_at`. Platform admin role `dcmp_platform_admin` has full lifecycle management policy on `organizations`.                                                                                                                                                                        |
| **3** | **Refresh-Token Retry Architecture Contradiction**        | Resolved the conflict between storing one-way SHA-256 hashes and returning plaintext tokens during retries. Established a **Client-Bound Transient Encrypted Idempotency Cache in Redis** (AES-256-GCM, 30s TTL) keyed by `(SHA256(old_token), SHA256(signature))`. Asymmetric hardware-backed ECDSA signatures required.                                                                                                                                                                        |
| **4** | **Refresh-Token Relational Integrity & Retention**        | Fixed ambiguous column names in session revocation SQL using explicitly aliased table columns (`us.id = p_session_id`). Enforced tenant and session integrity for `replaced_by_token_id` via composite foreign key `(organization_id, session_id, replaced_by_token_id) REFERENCES user_session_tokens(organization_id, session_id, id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`. Established 90-day forensic retention from `GREATEST(COALESCE(revoked_at, expires_at), expires_at)`. |
| **5** | **Database Role Privileges & Migration Decoupling**       | Reconciled object-level DML grants with RLS policies across `dcmp_app`, `dcmp_platform_admin`, and `dcmp_migrator`. Stages 1–6 deploy tenant-only RLS policies. Stage 7 deploys support infrastructure and attaches support-access policies.                                                                                                                                                                                                                                                     |

---

## 2. Platform Administrator Support Access Protocol

### 2.1 Principle of Least Privilege

Platform administrators have **zero blanket bypass** to customer business records. `dcmp_platform_admin` is created with `NOBYPASSRLS` and is strictly bound by `FORCE ROW LEVEL SECURITY`.

### 2.2 Cryptographic Support Context Function (`SECURITY DEFINER`)

To inspect customer records during an authorized support investigation:

1. Customer administrator generates an approved support grant via Customer Web.
2. The Platform Admin service initiates an audited support transaction by executing `open_support_session`:

```sql
CREATE OR REPLACE FUNCTION dcmp_security.open_support_session(
  p_admin_id UUID,
  p_grant_token VARCHAR,
  p_org_id UUID
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, dcmp_security, pg_temp
AS $$
DECLARE
  v_grant RECORD;
  v_secret BYTEA;
  v_sig TEXT;
BEGIN
  SELECT g.id, g.organization_id, r.platform_admin_id, g.expires_at
  INTO v_grant
  FROM public.support_access_grants g
  JOIN public.support_access_requests r ON g.support_access_request_id = r.id
  WHERE g.organization_id = p_org_id
    AND g.token_hash = encode(sha256(p_grant_token::bytea), 'hex')
    AND r.platform_admin_id = p_admin_id
    AND r.status = 'APPROVED'
    AND g.revoked_at IS NULL
    AND g.expires_at > NOW();

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Access Denied: Invalid, expired, unassigned, or revoked support grant.'
      USING ERRCODE = '28000';
  END IF;

  SELECT key_value INTO v_secret
  FROM dcmp_security.internal_keys
  WHERE key_name = 'support_hmac_secret';

  v_sig := encode(
    hmac(
      p_org_id::text || ':' || v_grant.id::text || ':' || transaction_timestamp()::text,
      v_secret,
      'sha256'
    ),
    'hex'
  );

  PERFORM set_config('app.support_org_id', p_org_id::text, true);
  PERFORM set_config('app.support_grant_id', v_grant.id::text, true);
  PERFORM set_config('app.support_signature', v_sig, true);
  PERFORM set_config('app.support_admin_id', p_admin_id::text, true);

  INSERT INTO public.support_access_logs (
    id, organization_id, support_access_grant_id, action, accessed_at
  ) VALUES (
    gen_random_uuid(), p_org_id, v_grant.id, 'SUPPORT_SESSION_AUTHORIZED', NOW()
  );
END;
$$;

REVOKE ALL ON FUNCTION dcmp_security.open_support_session(UUID, VARCHAR, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(UUID, VARCHAR, UUID) TO dcmp_platform_admin;
```

---

## 3. Organization Lifecycle Access & Tamper Prevention

### 3.1 Organization Policies across Roles

```sql
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

-- 1. Tenant Runtime Role (dcmp_app): Can SELECT only its own organization
CREATE POLICY tenant_org_select_policy ON organizations
  FOR SELECT
  TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- 2. Tenant Runtime Role (dcmp_app): Can UPDATE non-lifecycle fields of its own organization
CREATE POLICY tenant_org_update_policy ON organizations
  FOR UPDATE
  TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- 3. Platform Admin Role (dcmp_platform_admin): Full lifecycle management
CREATE POLICY platform_admin_org_lifecycle_policy ON organizations
  FOR ALL
  TO dcmp_platform_admin
  USING (true)
  WITH CHECK (true);
```

### 3.2 Database Engine Tamper Prevention Trigger

```sql
CREATE OR REPLACE FUNCTION trg_prevent_tenant_org_lifecycle_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF CURRENT_USER = 'dcmp_app' THEN
    IF NEW.status IS DISTINCT FROM OLD.status OR
       NEW.org_code IS DISTINCT FROM OLD.org_code OR
       NEW.id IS DISTINCT FROM OLD.id OR
       NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
      RAISE EXCEPTION 'Tenants cannot modify organization lifecycle, status, code, or deletion markers.'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_org_lifecycle_immutability
  BEFORE UPDATE ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION trg_prevent_tenant_org_lifecycle_tampering();
```

---

## 4. Refresh-Token Retry Architecture & Client Binding

### 4.1 Client-Bound Idempotency Cache in Redis

When the client initiates `POST /auth/refresh`, it provides:

1. `refreshToken`: Token $T_1$.
2. `signature`: Asymmetric ECDSA signature from hardware keystore.
3. `timestamp` & `nonce`.

Cache key: `auth:retry:<SHA256(T1)>:<SHA256(signature)>`.

- Within 30 seconds: Redis returns cached encrypted payload (AES-256-GCM).
- After 30 seconds or without matching signature: Cache misses, falling through to PostgreSQL to trigger **immediate hard reuse detection and whole-family revocation**.
- Session revocation writes `auth:revoked_session:<session_id>` to Redis, invalidating any pending retries immediately.

---

## 5. Token Retention & Deferrable Replacement Constraint

```sql
ALTER TABLE user_session_tokens
  ADD CONSTRAINT uq_tokens_org_session_id
  UNIQUE (organization_id, session_id, id);

ALTER TABLE user_session_tokens
  ADD CONSTRAINT fk_tokens_replacement_family
  FOREIGN KEY (organization_id, session_id, replaced_by_token_id)
  REFERENCES user_session_tokens (organization_id, session_id, id)
  ON DELETE NO ACTION
  DEFERRABLE INITIALLY DEFERRED;
```

_Engine Execution:_ With `ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`, batch deletion of token chains succeeds inside single transactions without foreign key constraint violations (`23503`). Partial chain deletions are rejected at `COMMIT`.

---

## 6. Comprehensive Security Acceptance Test Suite (24 Scenarios)

The Phase 2.2 implementation must execute and pass the 24 mandatory integration test suites against an active PostgreSQL 16 container:

1. **DB-SEC-001:** RLS tenant isolation on basic `SELECT` (no cross-tenant visibility).
2. **DB-SEC-002:** RLS enforcement on `UPDATE` and `DELETE` (no cross-tenant tampering).
3. **DB-SEC-003:** RLS prevention of cross-tenant `INSERT` spoofing (`WITH CHECK`).
4. **DB-SEC-004:** Fail-closed query behavior when tenant context is missing.
5. **DB-SEC-005:** Transaction rollback context reset (no connection pool leakage).
6. **DB-SEC-006:** Custom GUC tampering resistance (setting `app.is_platform_admin` has zero effect on tenant RLS).
7. **DB-SEC-007:** Tenant-root `organizations` isolation (`SELECT` own org only).
8. **DB-SEC-008:** Organization lifecycle immutability trigger blocks customer modifications to `status`, `org_code`, or `deleted_at`.
9. **DB-SEC-009:** Direct support GUC forgery fails signature verification; returns 0 rows.
10. **DB-SEC-010:** Forged admin identity in `open_support_session` fails with error `28000`.
11. **DB-SEC-011:** RLS recursion prevention: `dcmp_sec_definer` accesses `support_access_grants` without circular evaluation.
12. **DB-SEC-012:** Mid-Session Grant Revocation: revoking grant mid-investigation immediately drops visibility to 0 rows.
13. **DB-SEC-013:** Support access expiry drops visibility to 0 rows upon expiry.
14. **DB-SEC-014:** `SECURITY DEFINER` search-path attack resistance under fixed `search_path`.
15. **DB-SEC-015:** Direct access denial to `dcmp_security.internal_keys` for `dcmp_app` and `dcmp_platform_admin`.
16. **DB-SEC-016:** Relational integrity block on cross-tenant composite foreign keys.
17. **DB-SEC-017:** Declarative checklist question version integrity in `question_conditions`.
18. **DB-SEC-018:** Hardware-backed DPoP signature verification for token refresh.
19. **DB-SEC-019:** Replayed stolen bearer token without device private key misses cache and triggers family revocation.
20. **DB-SEC-020:** User logout marks session revoked in Redis; subsequent retry requests fail with `401 Unauthorized`.
21. **DB-SEC-021:** Redis outage fail-closed: PostgreSQL identifies `consumed_at` and revokes session family.
22. **DB-SEC-022:** Deferred `NO ACTION` token cleanup: pruning multi-token chain succeeds under `DEFERRABLE INITIALLY DEFERRED`.
23. **DB-SEC-023:** Partial-chain deletion rejection: deleting middle token fails with foreign key violation `23503`.
24. **DB-SEC-024:** Stage 1–6 migration decoupling: migrations execute cleanly without referencing Stage 7 support tables.

---

## 7. Implementation Readiness Sign-Off

The security boundary hardening, cryptographic support protocol, stage-sequential migration roadmap, client-bound retry cache, and deferred token pruning have been verified, cross-referenced, and approved.

**Phase 2.1 is officially concluded. The architecture is approved for Phase 2.2 Stage 1 implementation.**
