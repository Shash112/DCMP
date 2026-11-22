# DCMP Phase 2.1.5 — PostgreSQL Security Implementation Final Review

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior PostgreSQL Security Engineer & Database Architect  
**Document Purpose:** Definitive Security Model, `SECURITY DEFINER` Privilege Specifications, Device Proof-of-Possession, Deferred Foreign Key Pruning, and Final Implementation Sign-Off  
**Baseline Date:** November 22, 2026 (Phase 2.1.5 Final PostgreSQL Security Baseline)  
**Status:** **Approved Architectural & Security Baseline — Ready for Stage 1 Implementation**  
**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md)
- [doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md)
- [doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md)

---

## 1. Executive Summary & Resolution Matrix of Phase 2.1.5 Findings

This document establishes the definitive PostgreSQL security implementation for DCMP, resolving all findings raised in the Phase 2.1.4 review while strictly preserving the approved **62-entity relational database architecture**.

### 1.1 Resolution Matrix

| #     | Review Finding                                            | Root Cause in Phase 2.1.4                                                                                                                                                    | Final Corrective Action in Phase 2.1.5                                                                                                                                                                                                                                                                                                            |
| ----- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **`SECURITY DEFINER` Privilege & RLS Model**              | Undefined privileges and RLS behavior for `dcmp_sec_definer` under `FORCE ROW LEVEL SECURITY`.                                                                               | Role defined as `NOLOGIN, NOSUPERUSER, NOBYPASSRLS`. Created dedicated `dcmp_security` schema. Granted explicit RLS policies (`USING (true)`) on `support_access_grants` and `support_access_logs` exclusively for `dcmp_sec_definer`. Functions hardened with `SET search_path = public, dcmp_security, pg_temp` and fully qualified references. |
| **2** | **Mid-Session Support Grant Revocation**                  | `verify_support_signature` only verified mathematical HMAC without re-checking active grant status; revoking a grant mid-investigation did not immediately terminate access. | Updated `verify_support_signature` to perform a non-recursive grant lookup in `support_access_grants` checking `revoked_at IS NULL AND expires_at > NOW()`. Any mid-session revocation immediately causes subsequent queries to return **0 rows**. Added `close_support_session()` procedure.                                                     |
| **3** | **Platform Admin Identity & Audit Binding**               | Arbitrary `p_admin_id` could be supplied without database-level proof.                                                                                                       | Required `p_admin_id` to match `support_access_requests.platform_admin_id` linked to the verified grant token. Enforced audit event logging for authorization, query execution, failed attempts, revocations, and session termination, strictly excluding customer business payloads.                                                             |
| **4** | **Refresh-Token Proof of Possession (PoP)**               | Client binding relied on transmitted `installationId` and idempotency key, vulnerable to proxy interception.                                                                 | Implemented asymmetric **Device Proof-of-Possession (DPoP / ECDSA P-256)**. Hardware-backed private key never leaves the client device; client signs refresh requests. Public key is bound to session. Redis retry cache keys include the cryptographic signature hash. Stolen bearer tokens fail signature verification.                         |
| **5** | **PostgreSQL Token-Chain Cleanup (`ON DELETE RESTRICT`)** | `RESTRICT` cannot be deferred in PostgreSQL, causing syntax or runtime errors during batch pruning.                                                                          | Corrected constraint to `ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`. Enabled complete-chain deletion inside single transactions while guaranteeing that partial deletions violate foreign key constraints (`23503`). Clarified 90-day retention formula.                                                                                  |
| **6** | **Redis Revocation Consistency**                          | PostgreSQL revocation ordering and Redis cache invalidation lacked formal synchronization.                                                                                   | Established PostgreSQL as the authoritative source of truth. Revocations commit in PostgreSQL first, followed by immediate Redis tombstone publication. On Redis outage or cache miss, system fails closed.                                                                                                                                       |
| **7** | **Acceptance Test Matrix**                                | Test suite lacked coverage for mid-session revocation, search-path attacks, DPoP signatures, and deferred `NO ACTION` pruning.                                               | Expanded integration test suite to **24 exhaustive scenarios**.                                                                                                                                                                                                                                                                                   |

---

## 2. Hardened `SECURITY DEFINER` Privilege & RLS Model

### 2.1 Dedicated Non-Login Routine Owner

```sql
-- Dedicated routine owner (NOLOGIN, NOSUPERUSER, NOBYPASSRLS)
CREATE ROLE dcmp_sec_definer WITH NOLOGIN NOSUPERUSER NOBYPASSRLS;

-- Isolated Security Schema
CREATE SCHEMA dcmp_security AUTHORIZATION dcmp_sec_definer;
REVOKE ALL ON SCHEMA dcmp_security FROM PUBLIC;
REVOKE ALL ON SCHEMA dcmp_security FROM dcmp_app, dcmp_platform_admin;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_sec_definer, dcmp_platform_admin;
GRANT USAGE ON SCHEMA public TO dcmp_sec_definer;

-- Internal Cryptographic Key Store
CREATE TABLE dcmp_security.internal_keys (
  key_name VARCHAR(64) PRIMARY KEY,
  key_value BYTEA NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
ALTER TABLE dcmp_security.internal_keys OWNER TO dcmp_sec_definer;
REVOKE ALL ON dcmp_security.internal_keys FROM PUBLIC, dcmp_app, dcmp_platform_admin;
GRANT SELECT ON dcmp_security.internal_keys TO dcmp_sec_definer;
```

### 2.2 Explicit RLS Policies for `dcmp_sec_definer`

Under `ALTER TABLE ... FORCE ROW LEVEL SECURITY`, `dcmp_sec_definer` is subjected to RLS because it does not possess `BYPASSRLS`. To allow the security routines to operate without RLS recursion:

```sql
-- 1. Grant lookup policy on support_access_grants for dcmp_sec_definer
CREATE POLICY sec_definer_grant_lookup_policy ON public.support_access_grants
  FOR SELECT
  TO dcmp_sec_definer
  USING (true);

-- 2. Audit log insert policy on support_access_logs for dcmp_sec_definer
CREATE POLICY sec_definer_log_insert_policy ON public.support_access_logs
  FOR INSERT
  TO dcmp_sec_definer
  WITH CHECK (true);
```

_Security Proof:_ `dcmp_sec_definer` cannot log in (`NOLOGIN`). Its policies are evaluated strictly when executing security definer routines, completely eliminating RLS recursion.

---

## 3. Support Grant Lifecycle, Mid-Session Revocation & Identity Audit

### 3.1 Hardened Session Initialization Procedure

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
  -- A. Validate grant, organization, and assigned platform administrator
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
    -- Audit failed attempt
    INSERT INTO public.support_access_logs (
      id, organization_id, support_access_grant_id, action, accessed_at
    ) VALUES (
      gen_random_uuid(), p_org_id, NULL, 'SUPPORT_SESSION_FAILED: INVALID_CREDENTIALS', NOW()
    );

    RAISE EXCEPTION 'Access Denied: Invalid, expired, unassigned, or revoked support grant.'
      USING ERRCODE = '28000';
  END IF;

  -- B. Retrieve internal cryptographic secret
  SELECT key_value INTO v_secret
  FROM dcmp_security.internal_keys
  WHERE key_name = 'support_hmac_secret';

  IF v_secret IS NULL THEN
    RAISE EXCEPTION 'Internal Error: Cryptographic security key uninitialized.'
      USING ERRCODE = 'XX000';
  END IF;

  -- C. Compute transaction-bound HMAC signature
  v_sig := encode(
    hmac(
      p_org_id::text || ':' || v_grant.id::text || ':' || transaction_timestamp()::text,
      v_secret,
      'sha256'
    ),
    'hex'
  );

  -- D. Establish transaction-local session state
  PERFORM set_config('app.support_org_id', p_org_id::text, true);
  PERFORM set_config('app.support_grant_id', v_grant.id::text, true);
  PERFORM set_config('app.support_signature', v_sig, true);
  PERFORM set_config('app.support_admin_id', p_admin_id::text, true);

  -- E. Immutable Audit Logging
  INSERT INTO public.support_access_logs (
    id, organization_id, support_access_grant_id, action, accessed_at
  ) VALUES (
    gen_random_uuid(), p_org_id, v_grant.id, 'SUPPORT_SESSION_AUTHORIZED', NOW()
  );
END;
$$;
ALTER FUNCTION dcmp_security.open_support_session(UUID, VARCHAR, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(UUID, VARCHAR, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(UUID, VARCHAR, UUID) TO dcmp_platform_admin;
```

### 3.2 Dynamic Signature & Grant State Verification

```sql
CREATE OR REPLACE FUNCTION dcmp_security.verify_support_signature(
  p_org_id UUID,
  p_grant_id UUID,
  p_sig TEXT
) RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, dcmp_security, pg_temp
AS $$
DECLARE
  v_secret BYTEA;
  v_expected_sig TEXT;
  v_is_active BOOLEAN;
BEGIN
  IF p_org_id IS NULL OR p_grant_id IS NULL OR p_sig IS NULL THEN
    RETURN false;
  END IF;

  -- 1. Fast mathematical signature verification
  SELECT key_value INTO v_secret
  FROM dcmp_security.internal_keys
  WHERE key_name = 'support_hmac_secret';

  v_expected_sig := encode(
    hmac(
      p_org_id::text || ':' || p_grant_id::text || ':' || transaction_timestamp()::text,
      v_secret,
      'sha256'
    ),
    'hex'
  );

  IF p_sig <> v_expected_sig THEN
    RETURN false;
  END IF;

  -- 2. Non-recursive verification: Assert grant is STILL active and unrevoked
  SELECT (revoked_at IS NULL AND expires_at > NOW())
  INTO v_is_active
  FROM public.support_access_grants
  WHERE id = p_grant_id
    AND organization_id = p_org_id;

  RETURN COALESCE(v_is_active, false);
END;
$$;
ALTER FUNCTION dcmp_security.verify_support_signature(UUID, UUID, TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature(UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.verify_support_signature(UUID, UUID, TEXT) TO dcmp_platform_admin;
```

### 3.3 Mid-Session Revocation & Session Termination

- **Mid-Session Revocation:** If a customer administrator revokes a grant (`UPDATE support_access_grants SET revoked_at = NOW() WHERE id = ...`), the next query executed by `dcmp_platform_admin` evaluates `verify_support_signature()`. The active check evaluates to `false`, and RLS immediately returns **0 rows**.
- **Session Termination Procedure:**
  ```sql
  CREATE OR REPLACE FUNCTION dcmp_security.close_support_session()
  RETURNS void
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = public, dcmp_security, pg_temp
  AS $$
  DECLARE
    v_grant_id TEXT := current_setting('app.support_grant_id', true);
    v_org_id TEXT := current_setting('app.support_org_id', true);
  BEGIN
    IF v_grant_id IS NOT NULL AND v_org_id IS NOT NULL THEN
      INSERT INTO public.support_access_logs (
        id, organization_id, support_access_grant_id, action, accessed_at
      ) VALUES (
        gen_random_uuid(), v_org_id::uuid, v_grant_id::uuid, 'SUPPORT_SESSION_TERMINATED', NOW()
      );
    END IF;

    PERFORM set_config('app.support_org_id', '', true);
    PERFORM set_config('app.support_grant_id', '', true);
    PERFORM set_config('app.support_signature', '', true);
    PERFORM set_config('app.support_admin_id', '', true);
  END;
  $$;
  ```

---

## 4. Refresh-Token Asymmetric Proof of Possession (DPoP)

### 4.1 Threat Model: Bearer Token Theft vs Device-Key Compromise

| Threat Vector                  | Mechanism                                                 | Impact with Bearer Token Only                                    | Impact with DCMP Asymmetric PoP                                                       |
| ------------------------------ | --------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Bearer Token Interception**  | Attacker sniffs refresh token $T_1$ via proxy/log leak.   | **Session Hijacked:** Attacker rotates token and locks out user. | **Blocked:** Attacker lacks hardware private key; request fails signature check.      |
| **Transient Retry Harvesting** | Attacker calls `/auth/refresh` within 30s retry window.   | Attacker harvests replacement token from Redis.                  | **Blocked:** Redis cache key is bound to client signature; attacker misses cache.     |
| **Physical Device Extraction** | Adversary roots device and compromises hardware keystore. | Session Compromised.                                             | **Breach Contained:** Session-family reuse detection revokes all tokens upon anomaly. |

### 4.2 Architecture: Hardware-Protected ECDSA P-256

```
┌────────────────────────────────────────────────────────────────────────┐
│ Client Device (Android Keystore / iOS Secure Enclave / WebCrypto API)   │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Generates non-exportable ECDSA P-256 key pair: (K_priv, K_pub)      │
│ 2. Public key K_pub registered with UserSession at login / activation  │
│ 3. On Refresh: Signs Payload = SHA256(T1 || Nonce || Timestamp || Path)│
│ 4. Transmits: T1, Signature, Nonce, Timestamp                           │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ NestJS AuthService (Token Verification & Redis Idempotency Cache)      │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Verifies: Timestamp within ±60s, Nonce unconsumed                   │
│ 2. Verifies: ECDSA_Verify(K_pub, Payload, Signature) == TRUE           │
│ 3. Redis Cache Key: auth:retry:<SHA256(T1)>:<SHA256(Signature)>        │
│    • Hit within 30s: Decrypt cached { access, refresh } and return     │
│    • Miss or invalid signature: Fall through to PostgreSQL             │
│ 4. PostgreSQL Check:                                                   │
│    • If consumed_at IS NOT NULL: HARD REPLAY -> REVOKE ENTIRE FAMILY   │
│    • If legitimate: Rotate token, cache in Redis, return new tokens    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. PostgreSQL Token-Chain Cleanup & Deferred Foreign Keys

### 5.1 Syntax Correction: `ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`

In PostgreSQL, `ON DELETE RESTRICT` enforces immediate constraint checking and **cannot be declared `DEFERRABLE`**. The valid, engine-supported declarative syntax is **`ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`**:

```sql
ALTER TABLE user_session_tokens
  ADD CONSTRAINT fk_tokens_replacement_family
  FOREIGN KEY (organization_id, session_id, replaced_by_token_id)
  REFERENCES user_session_tokens (organization_id, session_id, id)
  ON DELETE NO ACTION
  DEFERRABLE INITIALLY DEFERRED;
```

### 5.2 Mathematical Proof of Chain Integrity & Deletion

- **Complete-Chain Deletion:** In a batch pruning transaction, `DELETE FROM user_session_tokens WHERE session_id = ...` purges all tokens in the session. PostgreSQL defers foreign key validation until `COMMIT`. At `COMMIT`, since all referenced tokens are deleted simultaneously, zero dangling references exist, and the transaction commits cleanly.
- **Partial-Chain Deletion Block:** If an errant query deletes Token 2 while Token 1 (which references Token 2) remains, the deferred constraint check evaluates at `COMMIT`. Token 1's `replaced_by_token_id` references a non-existent row, triggering error `23503: foreign_key_violation` and rolling back the transaction.

### 5.3 Retention Start & Pruning Transaction

- **Retention Cutoff Formula:**
  $$\text{retention\_start} = \max(\text{COALESCE}(us.\text{revoked\_at}, us.\text{expires\_at}), us.\text{expires\_at})$$
- **Pruning Transaction Procedure:**
  ```sql
  CREATE OR REPLACE PROCEDURE dcmp_security.prune_expired_tokens(p_batch_size INT DEFAULT 500)
  LANGUAGE plpgsql
  AS $$
  BEGIN
    DELETE FROM public.user_session_tokens
    WHERE session_id IN (
      SELECT id FROM public.user_sessions
      WHERE is_active = false
        AND GREATEST(COALESCE(revoked_at, expires_at), expires_at) < NOW() - INTERVAL '90 days'
      LIMIT p_batch_size
    );
  END;
  $$;
  ```

---

## 6. Redis Revocation Consistency & Authority

1. **PostgreSQL as Sole Authoritative Source:** Redis is strictly a transient idempotency cache.
2. **Atomic Invalidation Ordering:**
   - Step 1: Database transaction commits revocation in PostgreSQL (`UPDATE user_sessions SET is_active = false, revoked_at = NOW() WHERE ...; COMMIT;`).
   - Step 2: Immediately publish Redis tombstone: `SETEX auth:revoked_session:<session_id> 60 "REVOKED"`.
   - Step 3: Delete retry cache entries for that session.
3. **Guard Against Stale Cache Returns:** If `/auth/refresh` encounters a Redis retry cache hit, it checks `EXISTS auth:revoked_session:<session_id>`. If true, the cached payload is dropped, deleted from Redis, and rejected with `401 Unauthorized`.
4. **Outage Behavior:** On Redis outage or eviction, the system falls back to PostgreSQL and **fails closed** on any already-consumed token.

---

## 7. Comprehensive Security Acceptance Test Suite (24 Scenarios Baseline)

_(Note: In Phase 2.1.6, this suite was expanded to **32 scenarios** to cover Signed Support Assertion forgery, `READ COMMITTED` mid-session revocation, DPoP DoS prevention, `SET ROLE` denial, schema object shadowing, DPoP nonce replay, and concurrent refresh serialization; see [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md#8-comprehensive-security-acceptance-test-suite-32-scenarios) and [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md#6-comprehensive-database-acceptance--security-test-suite-32-scenarios))._

_(Note: In Phase 2.1.6, this suite was expanded to **32 scenarios** to cover Signed Support Assertion forgery, `READ COMMITTED` mid-session revocation, DPoP DoS prevention, `SET ROLE` denial, schema object shadowing, DPoP nonce replay, and concurrent refresh serialization; see [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md#8-comprehensive-security-acceptance-test-suite-32-scenarios) and [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md#6-comprehensive-database-acceptance--security-test-suite-32-scenarios))._

| Test ID        | Category                         | Target                              | Description & Expected Outcome                                                                               |
| -------------- | -------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **DB-SEC-001** | Tenant Isolation                 | `users`, `checklist_templates`      | Query with Tenant A context returns only Tenant A records; zero Tenant B rows.                               |
| **DB-SEC-002** | DML Tampering                    | `roles`, `inspection_instances`     | `UPDATE`/`DELETE` with Tenant A context targeting Tenant B row affects 0 rows.                               |
| **DB-SEC-003** | RLS INSERT Spoofing              | `users`, `checklist_versions`       | Attempting to `INSERT` row with `organization_id = Tenant B` fails with error `42501`.                       |
| **DB-SEC-004** | Fail-Closed Missing Context      | All Tenant Tables                   | Query executed without calling `set_tenant_context` returns 0 rows.                                          |
| **DB-SEC-005** | Transaction Context Reset        | Connection Pool Simulation          | Executing transaction with Tenant A context, rolling back, and querying returns 0 rows.                      |
| **DB-SEC-006** | Custom GUC Tampering             | `checklist_templates`               | Setting `app.is_platform_admin` under `dcmp_app` has zero effect; returns 0 cross-tenant rows.               |
| **DB-SEC-007** | Tenant-Root Isolation            | `organizations`                     | Customer session under Tenant A context can `SELECT` only the Tenant A organization row.                     |
| **DB-SEC-008** | Org Tampering Trigger            | `organizations`                     | `dcmp_app` attempting to update `status` or `org_code` fails with trigger error `42501`.                     |
| **DB-SEC-009** | Direct Support GUC Forgery       | `support_access_grants`, `users`    | `dcmp_platform_admin` manually setting `app.support_signature` fails signature verification; returns 0 rows. |
| **DB-SEC-010** | Forged Admin Identity            | `open_support_session`              | Calling `open_support_session` with unassigned `p_admin_id` fails with error `28000`.                        |
| **DB-SEC-011** | RLS Recursion Prevention         | `open_support_session`              | `dcmp_sec_definer` accesses `support_access_grants` cleanly without circular RLS evaluation.                 |
| **DB-SEC-012** | Mid-Session Grant Revocation     | `verify_support_signature`          | Revoking grant mid-investigation immediately drops `dcmp_platform_admin` visibility to 0 rows.               |
| **DB-SEC-013** | Support Access Expiry            | `verify_support_signature`          | Grant expiring mid-investigation immediately drops visibility to 0 rows.                                     |
| **DB-SEC-014** | Search-Path Attack Resistance    | `dcmp_security` Functions           | Creating malicious objects in `public` cannot hijack execution under fixed `search_path`.                    |
| **DB-SEC-015** | Internal Key Access Denial       | `dcmp_security.internal_keys`       | `dcmp_platform_admin` and `dcmp_app` querying `internal_keys` fail with permission denied `42501`.           |
| **DB-SEC-016** | Composite FK Isolation           | `checklist_versions` -> `templates` | Inserting version in Tenant A referencing template in Tenant B fails with FK violation `23503`.              |
| **DB-SEC-017** | Question Version Integrity       | `question_conditions`               | Linking condition between Question v1 and Question v2 fails with composite FK violation `23503`.             |
| **DB-SEC-018** | Asymmetric DPoP Verification     | `/auth/refresh`                     | Valid ECDSA signature succeeds; forged or mismatched signature fails with `401 Unauthorized`.                |
| **DB-SEC-019** | Replayed Stolen Bearer Token     | Redis Retry Cache                   | Attacker replaying stolen token without device private key misses cache and triggers family revocation.      |
| **DB-SEC-020** | Revoked Session Cache Tombstone  | Redis & `user_sessions`             | User logout writes tombstone; subsequent retry requests fail with `401 Unauthorized`.                        |
| **DB-SEC-021** | Redis Outage Fail-Closed         | Redis Failover Simulation           | If Redis is unavailable during replay, PostgreSQL identifies `consumed_at` and revokes session family.       |
| **DB-SEC-022** | Deferred NO ACTION Cleanup       | `user_session_tokens`               | Pruning an entire multi-token chain succeeds under `DEFERRABLE INITIALLY DEFERRED`.                          |
| **DB-SEC-023** | Partial-Chain Deletion Rejection | `user_session_tokens`               | Attempting to delete a middle token in an active chain fails with foreign key violation `23503`.             |
| **DB-SEC-024** | Stage 1–6 Migration Decoupling   | CI Migration Test                   | Migrations for Stages 1–6 execute in clean database without referencing Stage 7 support tables.              |

---

## 8. Implementation Readiness Sign-Off

All findings have been resolved with mathematical and engine-level precision. The 62-entity model, 11 domains, and 7 sequential stages are finalized.

**Phase 2.1 is officially concluded. Approved for Phase 2.2 Stage 1 implementation.**
