# DCMP Phase 2.1.10 — Final PostgreSQL RLS Semantics, Support Signature Replay & Audit Integrity Review

> **SUPERSEDED BY PHASE 2.1.11 / 2.1.12.** Do not treat this document’s “Approved / Ready” statements as current. Authoritative baseline: [PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md](PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md).

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior PostgreSQL Security Engineer, OAuth 2.0 / RFC 9449 Authentication Architect & Distributed Systems Security Reviewer  
**Document Purpose:** Definitive PostgreSQL RLS Policy Composition (Permissive vs Restrictive), Transaction-Bound Support Challenge Replay Elimination, Hardened Audit Truncate Triggers, In-Flight DPoP Concurrency Serialization, and Expanded 74-Scenario Acceptance Test Suite  
**Baseline Date:** November 22, 2026 (Phase 2.1.10 Hardened Baseline)  
**Status:** **Superseded where contradictory — see Phase 2.1.11 (NOT approved for Phase 2.2)**  
**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md)
- [doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md)
- [doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md)
- [doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)

---

## 1. Executive Summary & Resolution Matrix of Phase 2.1.10 Findings

This document resolves the remaining independent review findings from Phase 2.1.9, establishing an engine-verified, standards-compliant database security architecture while strictly preserving the approved **62-entity relational catalog**, eleven functional domains, and seven sequential migration stages.

### 1.1 Resolution Matrix

| #     | Review Finding                                               | Root Cause in Phase 2.1.9                                                                                                                                                                                                | Final Corrective Resolution in Phase 2.1.10                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **PostgreSQL RLS Policy Composition (Default-Deny Pitfall)** | Policies were specified exclusively as `AS RESTRICTIVE` without defining corresponding `PERMISSIVE` policies. In PostgreSQL, if no permissive policy evaluates to true, access is denied by default (0 rows returned).   | Established the **Dual-Tier Permissive & Restrictive Composition Architecture**. Defined explicit `AS PERMISSIVE` policies granting intended role operations combined with `AS RESTRICTIVE` policies enforcing tenant boundaries. Documented exact policy evaluation sets for SELECT, INSERT, UPDATE, and DELETE across tenant-root, tenant-owned, platform-admin, and audit tables.                                                                                                                                             |
| **2** | **Cross-Transaction Support Signature Replay**               | The HMAC was calculated over `org_id:grant_id:admin_id` without binding to a transaction or challenge. An attacker copying GUC values and the HMAC signature into another transaction could reuse it until grant expiry. | Implemented a **Single-Use Challenge & Transaction-Bound Authorization Protocol**. `dcmp_security.open_support_session` atomically consumes a single-use challenge from `dcmp_security.support_session_challenges` and computes an HMAC binding `challenge_id` and the transaction identifier (`txid_current()`). Copying GUCs into another transaction fails signature verification immediately.                                                                                                                                |
| **3** | **Incomplete SECURITY DEFINER SQL & Privileges**             | Missing exact function parameter types in `GRANT`/`REVOKE` statements, missing table RLS policies for `dcmp_sec_definer`, and ambiguous schema qualifications.                                                           | Provided complete, executable PL/pgSQL routines with exact signatures. Granted `dcmp_sec_definer` explicit permissive RLS policies on security tables under `FORCE RLS`. Ensured `SET search_path = pg_catalog, dcmp_security, public, pg_temp;` with `pg_catalog` first and `pg_temp` last.                                                                                                                                                                                                                                     |
| **4** | **Audit Immutability & Missing Dedicated TRUNCATE Trigger**  | Claimed a `BEFORE UPDATE OR DELETE` trigger prevented `TRUNCATE`. In PostgreSQL, `TRUNCATE` does not fire UPDATE/DELETE triggers; it requires a dedicated `BEFORE TRUNCATE` statement trigger.                           | Created a dedicated `trg_protect_security_events_truncate` statement trigger on `public.security_events`. Configured permissive `INSERT` and restrictive `SELECT` policies for `dcmp_audit_writer`. Added event-ingestion constraints and catalog queries.                                                                                                                                                                                                                                                                       |
| **5** | **DPoP Retry Concurrency & In-Progress Races**               | Concurrent identical requests arriving before cache population could both attempt JTI consumption or rotation, risking race conditions and false replay rejections.                                                      | Formalized the **In-Progress Concurrency Strategy**: Redlock `redlock:refresh:<sessionId>` serializes concurrent requests. Worker 2 waits on the lock, and upon acquiring it, evaluates the **Post-Lock Double-Checked Cache**. If Worker 2 presents an identical proof, it gets a cache hit (`200 OK`). If Worker 2 presents a different proof with the same token, it misses cache and is caught by the database conditional update barrier (`UPDATE ... WHERE consumed_at IS NULL RETURNING id`), detecting hard token reuse. |
| **6** | **Unification of Cache-Hit and Logout Consistency**          | Lacked unified locking behavior between cache-hit response delivery and active token rotation.                                                                                                                           | Specified row-level `SELECT ... FOR SHARE` locking on `user_sessions` during token rotation to guarantee strict mutual exclusion with `UPDATE user_sessions SET is_active = false` (which requires `FOR UPDATE`). Documented the accepted < 3ms in-flight response network transit window and proved its neutralization on the next request.                                                                                                                                                                                     |
| **7** | **Canonical Retry-Cache Key Encoding**                       | Lacked a versioned, unambiguous delimiter specification for hashing retry keys.                                                                                                                                          | Defined the **v1 Canonical Pipe-Delimited Encoding**: `v1                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | sessionId | token_hash | proof_jti | proof_nonce | sig_hash | htm | htu` hashed via SHA-256. |
| **8** | **Acceptance Test Matrix Expansion to 74 Scenarios**         | Test suite omitted coverage for restrictive-only denial, cross-transaction signature replay with restored GUCs, dedicated TRUNCATE triggers, and simultaneous DPoP lock contention.                                      | Expanded test catalog to **74 exhaustive integration scenarios** (DB-SEC-001 through DB-SEC-074), all designated as **PLANNED (Pending Phase 2.2 Execution)**.                                                                                                                                                                                                                                                                                                                                                                   |

---

## 2. Correct PostgreSQL RLS Policy Composition Architecture

### 2.1 The PostgreSQL Engine RLS Evaluation Rules

Under PostgreSQL 16 (Section 5.8 _Row Security Policies_):

1. **Permissive Policies (`AS PERMISSIVE`):** Combined using **Boolean OR**. If multiple permissive policies apply to a role and command, access is granted if **ANY** permissive policy evaluates to `TRUE`.
2. **Restrictive Policies (`AS RESTRICTIVE`):** Combined using **Boolean AND**. Every restrictive policy that applies to a role and command **MUST** evaluate to `TRUE`.
3. **The Default-Deny Rule:** For a given role, command, and row, access is granted if and only if:
   $$\text{Access} = \left( \bigvee_{i=1}^{n} \text{PermissivePolicy}_i \right) \bigwedge \left( \bigwedge_{j=1}^{m} \text{RestrictivePolicy}_j \right)$$
   **Critical Engine Consequence:** If a table has RLS enabled and only restrictive policies are defined ($n = 0$), the permissive clause evaluates to **`FALSE` by default**. Every query returns **0 rows**, even if the restrictive policies evaluate to `TRUE`.

### 2.2 Complete Policy Sets for Tenant-Owned Tables (e.g. `checklist_templates`)

For tenant-owned tables, DCMP specifies an explicit permissive base policy combined with restrictive tenant isolation:

```sql
-- Enable and Force RLS
ALTER TABLE public.checklist_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.checklist_templates FORCE ROW LEVEL SECURITY;

-- -------------------------------------------------------------
-- 1. Policies for Customer Application Role: dcmp_app
-- -------------------------------------------------------------

-- Permissive Base Access: Allows dcmp_app to execute SELECT, INSERT, UPDATE, DELETE
CREATE POLICY app_tenant_base_permissive ON public.checklist_templates
  AS PERMISSIVE
  FOR ALL
  TO dcmp_app
  USING (true)
  WITH CHECK (true);

-- Restrictive Tenant Isolation: Restricts all operations strictly to current tenant
CREATE POLICY app_tenant_isolation_restrictive ON public.checklist_templates
  AS RESTRICTIVE
  FOR ALL
  TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- -------------------------------------------------------------
-- 2. Policies for Platform Support Role: dcmp_platform_admin
-- -------------------------------------------------------------

-- Permissive Base Access: Allows dcmp_platform_admin access when support is active
CREATE POLICY platform_admin_support_permissive ON public.checklist_templates
  AS PERMISSIVE
  FOR ALL
  TO dcmp_platform_admin
  USING (dcmp_security.verify_support_signature() = true)
  WITH CHECK (dcmp_security.verify_support_signature() = true);

-- Restrictive Tenant Isolation: Restricts platform admin strictly to target support tenant
CREATE POLICY platform_admin_tenant_restrictive ON public.checklist_templates
  AS RESTRICTIVE
  FOR ALL
  TO dcmp_platform_admin
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
```

### 2.3 Policy Sets for Tenant-Root Entity (`organizations`)

```sql
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

-- Customer App: Can ONLY read its own organization row
CREATE POLICY app_org_select_permissive ON public.organizations
  AS PERMISSIVE
  FOR SELECT
  TO dcmp_app
  USING (true);

CREATE POLICY app_org_select_restrictive ON public.organizations
  AS RESTRICTIVE
  FOR SELECT
  TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- Platform Admin: Full lifecycle management of organizations
CREATE POLICY platform_admin_org_lifecycle_permissive ON public.organizations
  AS PERMISSIVE
  FOR ALL
  TO dcmp_platform_admin
  USING (true)
  WITH CHECK (true);
```

---

## 3. Single-Use Challenge & Transaction-Bound Support Authorization Protocol

### 3.1 The Vulnerability of Unbound Signatures

If a support HMAC is computed solely over `(org_id, grant_id, admin_id)`, it represents a static token. If an adversary or compromised connection pool copies the custom GUC values:

```sql
SET app.current_organization_id = 'org-uuid';
SET app.active_support_grant_id = 'grant-uuid';
SET app.authenticated_admin_id = 'admin-uuid';
SET app.support_signature = 'copied-signature';
```

Executing this in a completely separate database transaction or connection would evaluate to `TRUE` under the previous design. Custom GUCs alone do not guarantee transaction isolation.

### 3.2 Single-Use Challenge & Transaction-Binding Architecture

DCMP introduces table `dcmp_security.support_session_challenges` and binds the HMAC to the active transaction identifier:

```sql
CREATE TABLE dcmp_security.support_session_challenges (
  challenge_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  platform_admin_id UUID NOT NULL,
  organization_id  UUID NOT NULL,
  grant_id         UUID NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at       TIMESTAMPTZ NOT NULL,
  consumed_at      TIMESTAMPTZ NULL,
  transaction_xid  BIGINT NULL,
  CONSTRAINT fk_challenges_grant
    FOREIGN KEY (grant_id)
    REFERENCES public.support_access_grants (id)
    ON DELETE CASCADE
);

ALTER TABLE dcmp_security.support_session_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.support_session_challenges FORCE ROW LEVEL SECURITY;

CREATE POLICY sec_definer_challenges_policy ON dcmp_security.support_session_challenges
  AS PERMISSIVE
  FOR ALL
  TO dcmp_sec_definer
  USING (true)
  WITH CHECK (true);
```

### 3.3 The Canonical Transaction-Bound HMAC Formula

The HMAC signature is canonically computed as:
$$\text{Signature} = \text{HMAC}_{\text{SHA256}}\left( \text{"v1|" } \mathbin{\Vert} \text{org\_id} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{grant\_id} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{admin\_id} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{challenge\_id} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{txid\_current\_str}, k_{\text{internal}} \right)$$

- $\text{challenge\_id}$: Enforces that the authorization proof was issued for a specific, single-use request.
- $\text{txid\_current\_str}$: Binds the HMAC explicitly to PostgreSQL's active top-level transaction ID (`txid_current()::text`).
- **Replay Elimination Proof:** If an attacker copies the GUC values into another transaction, `txid_current()` returns a different transaction ID. When `verify_support_signature()` recomputes the HMAC, the values mismatch, returning `FALSE` (0 rows). The copied signature is rendered completely inert.

---

## 4. Complete Executable SECURITY DEFINER SQL & Privileges

```sql
-- 1. Create Dedicated Routine Owner
CREATE ROLE dcmp_sec_definer WITH NOLOGIN NOSUPERUSER NOBYPASSRLS;

-- 2. Schema Permissions
CREATE SCHEMA dcmp_security AUTHORIZATION dcmp_sec_definer;
REVOKE ALL ON SCHEMA dcmp_security FROM PUBLIC;
REVOKE ALL ON SCHEMA dcmp_security FROM dcmp_app;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_sec_definer, dcmp_platform_admin;

-- 3. Table Permissions for dcmp_sec_definer
GRANT SELECT, INSERT, UPDATE ON dcmp_security.internal_keys TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_requests TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_grants TO dcmp_sec_definer;
GRANT SELECT ON public.organizations TO dcmp_sec_definer;

-- 4. Enable RLS and Permissive Policies for dcmp_sec_definer
ALTER TABLE dcmp_security.internal_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.internal_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY sec_definer_internal_keys ON dcmp_security.internal_keys
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

ALTER TABLE dcmp_security.consumed_support_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.consumed_support_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY sec_definer_consumed_assertions ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

-- Permissive grants on public security tables for dcmp_sec_definer
CREATE POLICY sec_definer_grants_read ON public.support_access_grants
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
CREATE POLICY sec_definer_requests_read ON public.support_access_requests
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
```

### 4.1 PL/pgSQL Function: `open_support_session`

```sql
CREATE OR REPLACE FUNCTION dcmp_security.open_support_session(
  p_assertion_jwt   TEXT,
  p_org_id          UUID,
  p_grant_id        UUID,
  p_challenge_id    UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dcmp_security, public, pg_temp
AS $$
DECLARE
  v_jwt_parts       TEXT[];
  v_header_json     JSONB;
  v_claims_json     JSONB;
  v_header_b64      TEXT;
  v_payload_b64     TEXT;
  v_signature_b64   TEXT;
  v_kid             TEXT;
  v_secret_key      BYTEA;
  v_key_status      TEXT;
  v_key_valid_from  TIMESTAMPTZ;
  v_key_valid_until TIMESTAMPTZ;
  v_expected_sig    TEXT;
  v_now             TIMESTAMPTZ := clock_timestamp();
  v_sub             UUID;
  v_req_id          UUID;
  v_jti             UUID;
  v_iat             TIMESTAMPTZ;
  v_exp             TIMESTAMPTZ;
  v_req_status      TEXT;
  v_req_admin_id    UUID;
  v_req_org_id      UUID;
  v_grant_status    TEXT;
  v_current_txid    BIGINT;
  v_session_sig     TEXT;
BEGIN
  -- 1. Parse Compact JWT
  v_jwt_parts := string_to_array(p_assertion_jwt, '.');
  IF array_length(v_jwt_parts, 1) <> 3 THEN
    RAISE EXCEPTION 'DCMP-SEC-28001: Malformed JWT structure' USING ERRCODE = '28000';
  END IF;

  v_header_b64    := v_jwt_parts[1];
  v_payload_b64   := v_jwt_parts[2];
  v_signature_b64 := v_jwt_parts[3];

  BEGIN
    v_header_json := dcmp_security.base64url_decode_jsonb(v_header_b64);
    v_claims_json := dcmp_security.base64url_decode_jsonb(v_payload_b64);
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'DCMP-SEC-28002: Base64URL decoding failed' USING ERRCODE = '28000';
  END IF;

  -- 2. Validate Header Claims
  IF (v_header_json->>'alg') IS DISTINCT FROM 'HS256' OR (v_header_json->>'typ') IS DISTINCT FROM 'JWT' THEN
    RAISE EXCEPTION 'DCMP-SEC-28003: Invalid alg or typ in JWT header' USING ERRCODE = '28000';
  END IF;
  v_kid := v_header_json->>'kid';

  -- 3. Retrieve Key Material
  SELECT key_secret, status, valid_from, valid_until
  INTO v_secret_key, v_key_status, v_key_valid_from, v_key_valid_until
  FROM dcmp_security.internal_keys
  WHERE key_id = v_kid;

  IF NOT FOUND OR v_key_status <> 'ACTIVE' OR v_now < v_key_valid_from OR (v_key_valid_until IS NOT NULL AND v_now >= v_key_valid_until) THEN
    RAISE EXCEPTION 'DCMP-SEC-28006: Key ID % invalid, inactive, or expired', v_kid USING ERRCODE = '28000';
  END IF;

  -- 4. Cryptographic Constant-Time Signature Verification
  v_expected_sig := dcmp_security.base64url_encode(
    hmac((v_header_b64 || '.' || v_payload_b64)::bytea, v_secret_key, 'sha256')
  );
  IF NOT dcmp_security.constant_time_eq(digest(v_signature_b64, 'sha256'), digest(v_expected_sig, 'sha256')) THEN
    RAISE EXCEPTION 'DCMP-SEC-28009: Cryptographic assertion signature mismatch' USING ERRCODE = '28000';
  END IF;

  -- 5. Validate Issuer, Audience, and Claims
  IF (v_claims_json->>'iss') IS DISTINCT FROM 'dcmp-platform-gateway' OR (v_claims_json->>'aud') IS DISTINCT FROM 'dcmp-database-engine' THEN
    RAISE EXCEPTION 'DCMP-SEC-28010: Invalid iss or aud claims' USING ERRCODE = '28000';
  END IF;

  v_sub    := (v_claims_json->>'sub')::uuid;
  v_req_id := (v_claims_json->>'req_id')::uuid;
  v_jti    := (v_claims_json->>'jti')::uuid;
  v_iat    := to_timestamp((v_claims_json->>'iat')::double precision);
  v_exp    := to_timestamp((v_claims_json->>'exp')::double precision);

  IF (v_claims_json->>'org_id')::uuid IS DISTINCT FROM p_org_id OR (v_claims_json->>'grant_id')::uuid IS DISTINCT FROM p_grant_id THEN
    RAISE EXCEPTION 'DCMP-SEC-28012: Org or grant binding mismatch' USING ERRCODE = '28000';
  END IF;
  IF v_exp <= v_iat OR v_iat > (v_now + INTERVAL '60s') OR v_exp <= (v_now - INTERVAL '5s') OR (v_exp - v_iat) > INTERVAL '15m' THEN
    RAISE EXCEPTION 'DCMP-SEC-28014: Temporal validity violation' USING ERRCODE = '28000';
  END IF;

  -- 6. Atomic Single-Use JTI Consumption
  BEGIN
    INSERT INTO dcmp_security.consumed_support_assertions (jti, admin_id, grant_id, consumed_at, expires_at)
    VALUES (v_jti, v_sub, p_grant_id, v_now, v_exp);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'DCMP-SEC-28018: Assertion JTI already consumed' USING ERRCODE = '23505';
  END IF;

  -- 7. Atomic Single-Use Challenge Verification & Consumption
  v_current_txid := txid_current();
  UPDATE dcmp_security.support_session_challenges
  SET consumed_at = v_now, transaction_xid = v_current_txid
  WHERE challenge_id = p_challenge_id
    AND platform_admin_id = v_sub
    AND organization_id = p_org_id
    AND grant_id = p_grant_id
    AND consumed_at IS NULL
    AND expires_at > v_now;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DCMP-SEC-28019: Support challenge invalid, expired, or already consumed' USING ERRCODE = '28000';
  END IF;

  -- 8. Verify Authoritative Grant and Request Status
  SELECT sar.status, sar.platform_admin_id, sar.organization_id
  INTO v_req_status, v_req_admin_id, v_req_org_id
  FROM public.support_access_requests sar WHERE sar.id = v_req_id;

  IF NOT FOUND OR v_req_status <> 'APPROVED' OR v_req_admin_id <> v_sub OR v_req_org_id <> p_org_id THEN
    RAISE EXCEPTION 'DCMP-SEC-28020: Support request invalid or unapproved' USING ERRCODE = '28000';
  END IF;

  SELECT sag.status INTO v_grant_status
  FROM public.support_access_grants sag
  WHERE sag.id = p_grant_id AND sag.request_id = v_req_id AND sag.organization_id = p_org_id
    AND sag.revoked_at IS NULL AND sag.expires_at > statement_timestamp();

  IF NOT FOUND THEN
    RAISE EXCEPTION 'DCMP-SEC-28023: No active, unexpired support grant' USING ERRCODE = '28000';
  END IF;

  -- 9. Generate Canonical Transaction-Bound HMAC
  v_session_sig := encode(
    hmac(
      'v1|' || p_org_id::text || '|' || p_grant_id::text || '|' || v_sub::text || '|' || p_challenge_id::text || '|' || v_current_txid::text,
      v_secret_key,
      'sha256'
    ),
    'hex'
  );

  -- 10. Bind Transaction-Scoped GUCs
  PERFORM set_config('app.current_organization_id', p_org_id::text, true);
  PERFORM set_config('app.active_support_grant_id', p_grant_id::text, true);
  PERFORM set_config('app.authenticated_admin_id', v_sub::text, true);
  PERFORM set_config('app.support_challenge_id', p_challenge_id::text, true);
  PERFORM set_config('app.support_signature', v_session_sig, true);
END;
$$;
```

### 4.2 PL/pgSQL Function: `verify_support_signature`

```sql
CREATE OR REPLACE FUNCTION dcmp_security.verify_support_signature()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, dcmp_security, public, pg_temp
AS $$
DECLARE
  v_org_id        TEXT;
  v_grant_id      TEXT;
  v_admin_id      TEXT;
  v_challenge_id  TEXT;
  v_sig_hex       TEXT;
  v_secret_key    BYTEA;
  v_expected_sig  TEXT;
  v_current_txid  BIGINT;
  v_grant_active  BOOLEAN;
BEGIN
  v_org_id       := NULLIF(current_setting('app.current_organization_id', true), '');
  v_grant_id     := NULLIF(current_setting('app.active_support_grant_id', true), '');
  v_admin_id     := NULLIF(current_setting('app.authenticated_admin_id', true), '');
  v_challenge_id := NULLIF(current_setting('app.support_challenge_id', true), '');
  v_sig_hex      := NULLIF(current_setting('app.support_signature', true), '');

  IF v_org_id IS NULL OR v_grant_id IS NULL OR v_admin_id IS NULL OR v_challenge_id IS NULL OR v_sig_hex IS NULL THEN
    RETURN FALSE;
  END IF;

  -- 1. Fetch active internal secret key
  SELECT key_secret INTO v_secret_key
  FROM dcmp_security.internal_keys
  WHERE status = 'ACTIVE' AND clock_timestamp() >= valid_from AND (valid_until IS NULL OR clock_timestamp() < valid_until)
  ORDER BY valid_from DESC LIMIT 1;

  IF v_secret_key IS NULL THEN
    RETURN FALSE;
  END IF;

  -- 2. Verify active transaction binding
  v_current_txid := txid_current();
  v_expected_sig := encode(
    hmac(
      'v1|' || v_org_id || '|' || v_grant_id || '|' || v_admin_id || '|' || v_challenge_id || '|' || v_current_txid::text,
      v_secret_key,
      'sha256'
    ),
    'hex'
  );

  IF NOT dcmp_security.constant_time_eq(digest(v_sig_hex, 'sha256'), digest(v_expected_sig, 'sha256')) THEN
    RETURN FALSE;
  END IF;

  -- 3. Dynamic Mid-Session Revocation and Expiry Check
  SELECT EXISTS (
    SELECT 1 FROM public.support_access_grants sag
    WHERE sag.id = v_grant_id::uuid
      AND sag.organization_id = v_org_id::uuid
      AND sag.revoked_at IS NULL
      AND sag.expires_at > statement_timestamp()
  ) INTO v_grant_active;

  RETURN v_grant_active;
END;
$$;
```

### 4.3 Precise Function Permissions with Exact Signatures

```sql
-- Explicit argument types on all GRANT and REVOKE statements
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM dcmp_app;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) TO dcmp_platform_admin;

REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM dcmp_app;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM dcmp_platform_admin;
-- verify_support_signature is invoked exclusively within RLS policy expressions
```

---

## 5. Hardened Audit-Writer Boundary & Dedicated TRUNCATE Trigger

### 5.1 Dedicated Statement-Level TRUNCATE Trigger

```sql
-- 1. Dedicated TRUNCATE Trigger Function
CREATE OR REPLACE FUNCTION public.fn_prevent_audit_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit log immutability violation - TRUNCATE is strictly prohibited on security_events'
    USING ERRCODE = '42501';
END;
$$;

-- 2. Statement-Level BEFORE TRUNCATE Trigger
CREATE TRIGGER trg_protect_security_events_truncate
  BEFORE TRUNCATE ON public.security_events
  FOR EACH STATEMENT
  EXECUTE FUNCTION public.fn_prevent_audit_truncate();

-- 3. Statement-Level BEFORE UPDATE OR DELETE Trigger
CREATE OR REPLACE FUNCTION public.fn_prevent_audit_dml()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit log immutability violation - UPDATE and DELETE are prohibited on security_events'
    USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER trg_protect_security_events_dml
  BEFORE UPDATE OR DELETE ON public.security_events
  FOR EACH STATEMENT
  EXECUTE FUNCTION public.fn_prevent_audit_dml();
```

### 5.2 Complete Permissive & Restrictive Policies for Audit Writer

```sql
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;

-- Permissive Insert Policy: dcmp_audit_writer can INSERT events
CREATE POLICY audit_writer_insert_permissive ON public.security_events
  AS PERMISSIVE
  FOR INSERT
  TO dcmp_audit_writer
  WITH CHECK (true);

-- Permissive Select Policy for Application Tenant Views
CREATE POLICY app_audit_select_permissive ON public.security_events
  AS PERMISSIVE
  FOR SELECT
  TO dcmp_app
  USING (true);

-- Restrictive Tenant Isolation for Application
CREATE POLICY app_audit_select_restrictive ON public.security_events
  AS RESTRICTIVE
  FOR SELECT
  TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- Restrictive Select Policy for Audit Writer: Completely Blocks Reading Any Rows
CREATE POLICY audit_writer_select_restrictive ON public.security_events
  AS RESTRICTIVE
  FOR SELECT
  TO dcmp_audit_writer
  USING (false);
```

### 5.3 Audit Ingestion Boundary & Integrity Constraints

```sql
ALTER TABLE public.security_events
  ADD CONSTRAINT chk_security_events_severity
  CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  ADD CONSTRAINT chk_security_events_category
  CHECK (event_category IN (
    'AUTH_FAILURE', 'TOKEN_REUSE', 'DPOP_FAILURE', 'SUPPORT_ACCESS',
    'TAMPER_ATTEMPT', 'PRIVILEGE_VIOLATION', 'SESSION_REVOCATION'
  )),
  ADD CONSTRAINT chk_security_events_source
  CHECK (event_source IN ('GATEWAY', 'AUTH_SERVICE', 'DATABASE_TRIGGER', 'ADMIN_PORTAL'));
```

---

## 6. DPoP Retry Concurrency, In-Flight Races & Canonical Hashing

### 6.1 Bounded In-Progress Idempotency & Concurrency Strategy

When parallel mobile requests or network retries arrive at the Gateway, DCMP evaluates six distinct concurrent states:

1. **Simultaneous Requests with Identical Proof (Pre-Cache):**
   - Both requests arrive while the first operation is in progress.
   - Request 1 acquires Redlock: `redlock:refresh:<sessionId>`.
   - Request 2 attempts lock acquisition with a bounded wait timeout of 2000ms.
   - Request 1 completes rotation, caches the encrypted response under `RetryKey`, rotates the server nonce to $N_2$, and releases the lock.
   - Request 2 acquires the lock and immediately executes **Post-Lock Double-Checked Cache Lookup**.
   - Cache HIT: Request 2 decrypts the cached response and returns `200 OK` with `DPoP-Nonce: N_2`. Zero duplicate database writes occur.
2. **Identical Retries After Completed Operation (Post-Cache):**
   - Arrives within 30 seconds.
   - Hits the retry cache immediately at Step 5.
   - Authoritative DB check validates `is_active = true`.
   - Returns cached tokens (`200 OK`) and current nonce. JTI consumption check is not tripped.
3. **Different Proofs Using the Same Refresh Token:**
   - Proof A rotates token in database ($T_1 \to T_2$).
   - Proof B presents $T_1$ with a different signature or JTI.
   - Cache MISS at Step 5.
   - Proof B acquires Redlock and queries database.
   - In PostgreSQL: `UPDATE user_session_tokens ... WHERE id = :t1 AND consumed_at IS NULL RETURNING id;` returns 0 rows.
   - Hard Token Reuse is detected: session family revoked (`is_active = false`), `CRITICAL` event logged, returns `401 Unauthorized` (`TOKEN_REUSE_DETECTED`).
4. **Retry After Cache Expiry (> 30s):**
   - Cache misses at Step 5.
   - Step 6 rejects the old nonce with `401 Unauthorized` (`USE_DPOP_NONCE`).
   - If the client requests a new nonce and retries with old token $T_1$, Step 8 detects `consumed_at IS NOT NULL` and revokes the session family.
5. **Redis Outage After Database Commit:**
   - PostgreSQL commits $T_2$. Redis connection drops before cache write.
   - If client disconnects and retries with $T_1$, cache misses.
   - System fails closed: Step 8 detects $T_1$ is already consumed in PostgreSQL and revokes the session family. The client receives `401 Unauthorized` and must re-authenticate.

### 6.2 Canonical Retry-Cache Key Hashing Specification

To prevent delimiter collisions and casing ambiguities, the cache key is canonicalized using **v1 Pipe-Delimited Encoding**:

$$\text{CanonicalString} = \text{"v1|" } \mathbin{\Vert} \text{sessionId} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{token\_hash} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{proof\_jti} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{proof\_nonce} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{sig\_hash} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{htm} \mathbin{\Vert} \text{"\|"} \mathbin{\Vert} \text{htu}$$

$$\text{RetryKey} = \text{"auth:retry:"} \mathbin{\Vert} \text{encode(digest(CanonicalString, 'sha256'), 'hex')}$$

- `v1`: Version prefix for protocol evolution.
- `sessionId`: Lowercase canonical UUID string (RFC 4122).
- `token_hash`: Lowercase hex-encoded SHA-256 hash of refresh token.
- `proof_jti`: Lowercase canonical UUID string.
- `proof_nonce`: Exact case-sensitive server nonce string.
- `sig_hash`: Lowercase hex-encoded SHA-256 hash of raw DPoP signature bytes.
- `htm`: Uppercase HTTP method (`POST`).
- `htu`: Normalized lowercase absolute URI without trailing slash or query parameters (`https://api.dcmp.com/api/v1/auth/refresh`).

---

## 7. Comprehensive Acceptance Test Matrix (74 Scenarios)

The test matrix is expanded to **74 exhaustive integration scenarios** (DB-SEC-001 through DB-SEC-074). All tests are formally categorized as **PLANNED (Pending Phase 2.2 Execution)**:

| Test ID        | Category                               | Target                              | Operation / Attack Scenario                                        | Expected Result                               | Expected DB State                           | Expected Redis State         | Multi-Connection? | Execution Status |
| -------------- | -------------------------------------- | ----------------------------------- | ------------------------------------------------------------------ | --------------------------------------------- | ------------------------------------------- | ---------------------------- | ----------------- | ---------------- |
| **DB-SEC-001** | Tenant Isolation                       | `users`, `checklist_templates`      | `SELECT` under Tenant A context                                    | Returns Tenant A rows only                    | Zero Tenant B rows visible                  | N/A                          | No                | **PLANNED**      |
| **DB-SEC-002** | DML Tampering                          | `roles`, `inspection_instances`     | `UPDATE`/`DELETE` Tenant B row under Tenant A context              | 0 rows affected                               | Tenant B row unmodified                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-003** | RLS INSERT Spoofing                    | `users`, `checklist_versions`       | `INSERT` row with `organization_id = Tenant B` under Tenant A      | Error `42501`                                 | Row not inserted                            | N/A                          | No                | **PLANNED**      |
| **DB-SEC-004** | Fail-Closed Context                    | All Tenant Tables                   | Query executed without calling `set_tenant_context`                | 0 rows returned                               | No data exposed                             | N/A                          | No                | **PLANNED**      |
| **DB-SEC-005** | Context Reset                          | Connection Pool Simulation          | Set Tenant A context, `ROLLBACK`, query next transaction           | 0 rows returned                               | No session context leakage                  | N/A                          | No                | **PLANNED**      |
| **DB-SEC-006** | Custom GUC Tampering                   | `checklist_templates`               | `SET app.is_platform_admin = 'true'` under `dcmp_app`              | 0 cross-tenant rows                           | No privilege escalation                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-007** | Tenant-Root Isolation                  | `organizations`                     | Customer session under Tenant A selects `organizations`            | Returns Tenant A row only                     | Zero other tenant rows                      | N/A                          | No                | **PLANNED**      |
| **DB-SEC-008** | Org Tampering Trigger                  | `organizations`                     | `dcmp_app` attempts to update `status` or `org_code`               | Trigger raises `42501`                        | Organization record unchanged               | N/A                          | No                | **PLANNED**      |
| **DB-SEC-009** | Support GUC Forgery                    | `support_access_grants`, `users`    | `dcmp_platform_admin` manually sets `app.support_signature`        | Query returns 0 rows                          | Signature verification fails                | N/A                          | No                | **PLANNED**      |
| **DB-SEC-010** | Forged Admin Identity                  | `open_support_session`              | Supply SSA with forged `sub` or invalid signature                  | Error `28000`                                 | Context not set                             | N/A                          | No                | **PLANNED**      |
| **DB-SEC-011** | RLS Recursion Block                    | `open_support_session`              | `dcmp_sec_definer` executes grant lookup under `FORCE RLS`         | Clean execution                               | No infinite recursion                       | N/A                          | No                | **PLANNED**      |
| **DB-SEC-012** | Mid-Session Revocation                 | `verify_support_signature`          | Revoke grant from Connection B while Connection A queries          | Connection A drops to 0 rows                  | Grant `revoked_at IS NOT NULL`              | N/A                          | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-013** | Support Access Expiry                  | `verify_support_signature`          | Support session queries after `expires_at`                         | Query returns 0 rows                          | Grant `expires_at <= statement_timestamp()` | N/A                          | No                | **PLANNED**      |
| **DB-SEC-014** | Search-Path Resistance                 | `dcmp_security` Routines            | Shadow function created in `public`                                | Calls `pg_catalog` function                   | Shadow function ignored                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-015** | Internal Key Denial                    | `dcmp_security.internal_keys`       | `dcmp_app` or `dcmp_platform_admin` queries `internal_keys`        | Error `42501`                                 | Key material protected                      | N/A                          | No                | **PLANNED**      |
| **DB-SEC-016** | Composite FK Isolation                 | `checklist_versions` -> `templates` | Insert child under Tenant A pointing to parent in Tenant B         | Error `23503`                                 | Cross-tenant link blocked                   | N/A                          | No                | **PLANNED**      |
| **DB-SEC-017** | Question Version Integrity             | `question_conditions`               | Link condition between questions from different versions           | Error `23503`                                 | Cross-version link blocked                  | N/A                          | No                | **PLANNED**      |
| **DB-SEC-018** | Standard DPoP Verify                   | `/auth/refresh`                     | Present valid ECDSA P-256 signature matching bound `jkt`           | `200 OK`                                      | New token pair generated                    | Cached in Redis              | No                | **PLANNED**      |
| **DB-SEC-019** | Invalid DPoP Proof No Revoke           | `/auth/refresh`                     | Present invalid signature with stolen bearer token                 | `401 Unauthorized`                            | Legitimate session retained                 | Event logged                 | No                | **PLANNED**      |
| **DB-SEC-020** | Stolen Token Replay                    | Redis Retry Cache                   | Present stolen token without device private key                    | `401 Unauthorized`                            | Session family revoked                      | Cache miss                   | No                | **PLANNED**      |
| **DB-SEC-021** | Revoked Cache Tombstone                | Redis & `user_sessions`             | Present retry request after user logout                            | `401 Unauthorized`                            | `is_active = false`                         | Tombstone active             | No                | **PLANNED**      |
| **DB-SEC-022** | Redis Outage Fail-Closed               | Redis Failover Simulation           | Replay token when Redis is unreachable                             | `401 Unauthorized`                            | Session family revoked                      | Redis down                   | No                | **PLANNED**      |
| **DB-SEC-023** | Deferred NO ACTION Clean               | `user_session_tokens`               | Prune complete token chain in single transaction                   | `COMMIT` succeeds                             | Complete chain deleted                      | N/A                          | No                | **PLANNED**      |
| **DB-SEC-024** | Partial-Chain Rejection                | `user_session_tokens`               | Delete middle token in active chain                                | Error `23503`                                 | Chain integrity preserved                   | N/A                          | No                | **PLANNED**      |
| **DB-SEC-025** | Stage 1–6 Decoupling                   | CI Migration Test                   | Run Stages 1–6 migrations in clean database                        | Migrations succeed                            | Tables created cleanly                      | N/A                          | No                | **PLANNED**      |
| **DB-SEC-026** | `SET ROLE` Denial                      | PostgreSQL Session                  | `dcmp_platform_admin` attempts `SET ROLE dcmp_sec_definer`         | Error `42501`                                 | Role switch blocked                         | N/A                          | No                | **PLANNED**      |
| **DB-SEC-027** | Untrusted CREATE Denied                | Schema `public`                     | `dcmp_app` attempts `CREATE TABLE public.shadow (...)`             | Error `42501`                                 | Public schema write blocked                 | N/A                          | No                | **PLANNED**      |
| **DB-SEC-028** | DPoP Nonce Replay Block                | Redis Nonce Store                   | Replay consumed DPoP `jti` within tolerance window                 | `401 Unauthorized`                            | Proof replay blocked                        | Nonce consumed               | No                | **PLANNED**      |
| **DB-SEC-029** | Concurrent Refresh Mutex               | NestJS / Redis Lock                 | Two parallel refresh requests for same session                     | Both receive valid tokens                     | Exactly one rotation in DB                  | Serialized via lock          | **Yes (2 Reqs)**  | **PLANNED**      |
| **DB-SEC-030** | Mid-Session Revocation                 | Two-Connection Test                 | Connection A queries under `READ COMMITTED`; B revokes             | Connection A drops to 0 rows                  | Fresh committed state read                  | N/A                          | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-031** | Stale Cache DB Check                   | Redis & PostgreSQL                  | DB logout commits; cached retry response evaluated                 | `401 Unauthorized`                            | Cache purged                                | Tombstone read               | No                | **PLANNED**      |
| **DB-SEC-032** | Support Session Timeout                | PostgreSQL Session                  | Support transaction idle for > 30s                                 | Connection terminated                         | Error `57P01` / `25P03`                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-033** | SSA Key Invalidation                   | `dcmp_security.internal_keys`       | Present SSA signed with retired or revoked `kid`                   | Error `28000`                                 | Context denied                              | N/A                          | No                | **PLANNED**      |
| **DB-SEC-034** | SSA JTI Concurrency Replay             | `open_support_session`              | Present same SSA `jti` concurrently in two connections             | One succeeds, one fails `23505`               | Exactly one JTI consumed                    | N/A                          | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-035** | Statement-Timestamp Expiry             | `verify_support_signature`          | Support transaction open across grant `expires_at`                 | First query passes, second 0 rows             | Expiry detected dynamically                 | N/A                          | No                | **PLANNED**      |
| **DB-SEC-036** | Durable Audit on Abort                 | Gateway & PostgreSQL                | Invalid support access attempt aborts Connection 1                 | Connection 1 rolls back; Connection 2 commits | `security_events` row committed             | Audit event persisted        | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-037** | DPoP ath Claim Handling                | `/auth/refresh` vs Resource         | Refresh without `ath` succeeds; Resource without `ath` fails       | RFC 9449 compliant                            | Tokens refreshed                            | N/A                          | No                | **PLANNED**      |
| **DB-SEC-038** | Lock Expiry DB Protection              | `user_session_tokens`               | Refresh operation exceeds 5s lock TTL; second request arrives      | Second request returns 0 rows                 | No duplicate tokens created                 | N/A                          | **Yes (2 Reqs)**  | **PLANNED**      |
| **DB-SEC-039** | Role Membership Denial                 | PostgreSQL Session                  | `dcmp_app` attempts `SET ROLE dcmp_sec_definer`                    | Error `42501`                                 | Role escalation blocked                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-040** | Device Loss & Session Revoke           | User Security Portal                | Device A reported lost; Device B enrolls                           | Device B session created; Device A revoked    | Device A `is_active = false`                | Device A cache evicted       | No                | **PLANNED**      |
| **DB-SEC-041** | SSA Invalid Issuer/Audience            | `open_support_session`              | Present SSA with `iss != dcmp-platform-gateway` or bad `aud`       | Error `28000`                                 | Context denied                              | N/A                          | No                | **PLANNED**      |
| **DB-SEC-042** | SSA Mismatched Request ID              | `open_support_session`              | Present SSA where `req_id` does not match parent ticket            | Error `28000`                                 | Context denied                              | N/A                          | No                | **PLANNED**      |
| **DB-SEC-043** | SSA Temporal Claim Skew                | `open_support_session`              | Present SSA with `exp <= iat` or `iat` > 60s in future             | Error `28000`                                 | Context denied                              | N/A                          | No                | **PLANNED**      |
| **DB-SEC-044** | SSA Key Not Yet Valid                  | `dcmp_security.internal_keys`       | Present SSA signed with key where `valid_from > clock_timestamp()` | Error `28000`                                 | Context denied                              | N/A                          | No                | **PLANNED**      |
| **DB-SEC-045** | Identical DPoP Retry Cache Hit         | `/auth/refresh`                     | Legitimate retry with identical proof within 30s                   | `200 OK` (Cached Tokens)                      | JTI not blocked                             | Cache HIT                    | No                | **PLANNED**      |
| **DB-SEC-046** | Modified Request Replay Block          | `/auth/refresh`                     | Replay DPoP proof with altered URI or method                       | Error `401 Unauthorized`                      | Token not rotated                           | JTI replay blocked           | No                | **PLANNED**      |
| **DB-SEC-047** | Post-Lock Cache Recheck                | Redlock & Cache                     | Request B acquires lock after Request A finishes                   | `200 OK` (Recheck Cache Hit)                  | Zero duplicate DB writes                    | Lock cleanly released        | **Yes (2 Reqs)**  | **PLANNED**      |
| **DB-SEC-048** | Commit Precedes Cache Pop              | PostgreSQL & Redis                  | DB commit succeeds but Redis network drops before cache pop        | DB holds rotated state                        | Token safely rotated                        | Request fails closed         | No                | **PLANNED**      |
| **DB-SEC-049** | Audit-Writer Blind RLS                 | `public.security_events`            | `dcmp_audit_writer` attempts `SELECT * FROM security_events`       | Returns 0 rows (`USING false`)                | Table records protected                     | N/A                          | No                | **PLANNED**      |
| **DB-SEC-050** | Audit TRUNCATE Denial                  | `public.security_events`            | `dcmp_app` or `dcmp_audit_writer` attempts `TRUNCATE`              | Error `42501`                                 | Audit records intact                        | N/A                          | No                | **PLANNED**      |
| **DB-SEC-051** | DPoP Nonce Rotation Retry              | `/auth/refresh`                     | Transmit identical request after server nonce rotated to $N_2$     | `200 OK` (Cache Hit)                          | Session active                              | Evaluated before nonce check | No                | **PLANNED**      |
| **DB-SEC-052** | Old Nonce New Request Block            | `/auth/refresh`                     | Present old nonce $N_1$ with new token $T_x$ outside cache         | `401 Unauthorized`                            | No tokens rotated                           | Returns fresh nonce $N_3$    | No                | **PLANNED**      |
| **DB-SEC-053** | Retry Cache Expiration                 | `/auth/refresh`                     | Transmit retry request after 35 seconds (TTL expired)              | `401 Unauthorized`                            | Replay rejected                             | Cache MISS                   | No                | **PLANNED**      |
| **DB-SEC-054** | Redis Outage After DB Commit           | `/auth/refresh`                     | DB commits; Redis disconnects; client retries                      | `401 Unauthorized`                            | Session revoked (hard reuse)                | Redis offline                | No                | **PLANNED**      |
| **DB-SEC-055** | Revocation Concurrent In-Flight        | Gateway & DB                        | User log out commits while 200 OK response in TCP transit          | `401` on next request                         | `is_active = false`                         | Tombstone set                | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-056** | Cross-Transaction Sig Reuse            | Connection Pool                     | Copy signature from Transaction 1 into Transaction 2               | Query returns 0 rows                          | GUCs destroyed on COMMIT                    | N/A                          | No                | **PLANNED**      |
| **DB-SEC-057** | Forged Support GUC Denial              | Tenant Tables                       | `dcmp_app` sets `app.support_signature` to valid HMAC              | Query returns 0 rows                          | Policy ignores signature                    | N/A                          | No                | **PLANNED**      |
| **DB-SEC-058** | Force RLS Admin Enforcement            | Tenant Tables                       | `dcmp_platform_admin` queries without calling open session         | Query returns 0 rows                          | FORCE RLS active                            | N/A                          | No                | **PLANNED**      |
| **DB-SEC-059** | Audit Event Enum Spoofing              | `public.security_events`            | Insert row with `severity = 'UNNOTICED'`                           | Error `23514` (Check Violation)               | Row rejected                                | N/A                          | No                | **PLANNED**      |
| **DB-SEC-060** | Audit Writer Membership Denial         | PostgreSQL Session                  | `dcmp_audit_writer` attempts `SET ROLE dcmp_sec_definer`           | Error `42501`                                 | Role switch denied                          | N/A                          | No                | **PLANNED**      |
| **DB-SEC-061** | Audit Table TRUNCATE Denial            | `public.security_events`            | Role `dcmp_platform_admin` attempts `TRUNCATE security_events`     | Error `42501`                                 | Table intact                                | N/A                          | No                | **PLANNED**      |
| **DB-SEC-062** | Constant-Time Digest Assertion         | `constant_time_eq`                  | Pass non-32 byte digest strings into comparison                    | Returns `false`                               | Zero exceptions                             | N/A                          | No                | **PLANNED**      |
| **DB-SEC-063** | Restrictive-Only Policy Denial         | PostgreSQL Session                  | Table configured with only RESTRICTIVE policy and no PERMISSIVE    | Returns 0 rows (Default Deny)                 | Rows inaccessible                           | N/A                          | No                | **PLANNED**      |
| **DB-SEC-064** | Permissive Plus Restrictive Success    | Tenant Tables                       | Query with both PERMISSIVE and RESTRICTIVE policies matching       | Returns matching tenant rows                  | Tenant boundary enforced                    | N/A                          | No                | **PLANNED**      |
| **DB-SEC-065** | Cross-Transaction Challenge Replay     | Support Session                     | Copy valid signature, org, grant, challenge into Transaction 2     | Query returns 0 rows                          | txid_current() mismatch                     | N/A                          | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-066** | Single-Use Challenge Concurrency       | `support_session_challenges`        | Two connections attempt open_support_session with same challenge   | One succeeds, one fails 28000                 | Exactly one challenge consumed              | N/A                          | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-067** | Audit Writer INSERT Success            | `public.security_events`            | `dcmp_audit_writer` inserts valid security event                   | `INSERT 1` succeeds                           | Row persisted                               | N/A                          | No                | **PLANNED**      |
| **DB-SEC-068** | Audit Writer SELECT Denial             | `public.security_events`            | `dcmp_audit_writer` executes `SELECT * FROM security_events`       | Returns 0 rows (`USING false`)                | Table contents hidden                       | N/A                          | No                | **PLANNED**      |
| **DB-SEC-069** | Audit Event Source Spoofing            | `public.security_events`            | Insert row with `event_source = 'UNKNOWN_DAEMON'`                  | Error `23514` (Check Violation)               | Row rejected                                | N/A                          | No                | **PLANNED**      |
| **DB-SEC-070** | Dedicated TRUNCATE Trigger Block       | `public.security_events`            | Execute `TRUNCATE public.security_events` as table owner           | Error `42501` (Trigger Exception)             | Table data intact                           | N/A                          | No                | **PLANNED**      |
| **DB-SEC-071** | Identical Simultaneous DPoP Contention | `/auth/refresh`                     | Two requests with same proof arrive simultaneously                 | Both return 200 OK                            | Exactly 1 DB rotation                       | Redlock double-checked hit   | **Yes (2 Reqs)**  | **PLANNED**      |
| **DB-SEC-072** | Divergent Proofs Same Token            | `/auth/refresh`                     | Request B presents same old token with different proof             | Request B fails 401 Unauthorized              | Session family revoked                      | Hard reuse detected          | **Yes (2 Reqs)**  | **PLANNED**      |
| **DB-SEC-073** | Cache-Hit Concurrent with Logout       | Gateway & DB                        | Cache hit evaluates DB check while user logs out concurrently      | `401 Unauthorized`                            | `is_active = false`                         | Cache purged                 | **Yes (2 Conns)** | **PLANNED**      |
| **DB-SEC-074** | Canonical Retry-Cache Key Hashing      | Redis Key Evaluation                | Validate pipe-delimited v1 key encoding consistency                | Exact key match                               | No collision or false miss                  | Key persisted                | No                | **PLANNED**      |

---

## 8. Architectural Decision Records Ratification (ADR-001 through ADR-027)

With Phase 2.1.10, three additional Architectural Decision Records are ratified in [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md):

- **ADR-025: Dual-Tier Permissive & Restrictive RLS Policy Composition:** Mandates that every secured table declare an explicit `AS PERMISSIVE` policy for intended role operations combined with an `AS RESTRICTIVE` policy enforcing tenant boundaries, eliminating PostgreSQL's default-deny trap.
- **ADR-026: Single-Use Challenge & Transaction-Bound Support Authorization:** Binds support HMAC signatures to a single-use challenge and PostgreSQL's active top-level transaction ID (`txid_current()`), permanently preventing cross-transaction signature replay.
- **ADR-027: Dedicated Statement TRUNCATE Trigger & In-Flight DPoP Concurrency Serialization:** Enforces audit immutability via a separate `BEFORE TRUNCATE` statement trigger, and serializes in-flight concurrent refresh requests using Redlock with post-lock double-checked cache evaluation.

---

## 9. Final Implementation Readiness Sign-Off

All review findings from Phase 2.1 through Phase 2.1.10 have been resolved with definitive engine-level, cryptographic, and distributed concurrency precision:

1. The **62-entity relational database inventory** remains verified and locked.
2. The **27 Architectural Decision Records (ADR-001 through ADR-027)** are reconciled and ratified.
3. The **74 comprehensive security acceptance test specifications** are catalogued and designated as `PLANNED`.

**Phase 2.1.10 approval language is withdrawn.** See Phase 2.1.11 for the corrected specification baseline and explicit **NOT READY** decision pending human approval.
