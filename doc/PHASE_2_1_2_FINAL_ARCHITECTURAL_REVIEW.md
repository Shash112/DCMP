# DCMP Phase 2.1.2 — Final Database Architecture Review & Implementation Baseline

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Database Architect, PostgreSQL Security Engineer & Prisma Technical Lead  
**Document Purpose:** Definitive Architectural Corrections, 62-Entity Reconciled Inventory, Database Security Model, and Implementation Sign-Off  
**Baseline Date:** November 22, 2026 (Phase 2.1.5 Reconciled Security Baseline)  
**Status:** **Approved Architectural Baseline — Ready for Stage 1 Implementation**  
**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md)
- [doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md)
- [doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md)

---

## 1. Executive Summary & Resolution of Review Findings

This document establishes the definitive, corrected database architecture and security baseline for the **Digital Checklist Management Platform (DCMP)**, addressing all architectural findings identified in the Phase 2.1 reviews.

### 1.1 Resolution Matrix of Review Findings

| #      | Review Finding                                  | Root Cause                                                                                                                         | Final Corrective Action                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------ | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1**  | **Entity Classification Discrepancy**           | Text claimed 10 platform-global, 48 tenant-owned, and 10 Stage 1 RLS tables, while inventory contained 9, 49, and 11 respectively. | Recounted and reconciled all entities. Added `user_session_tokens` (#11) for token history, establishing an exact total of **62 entities**: **9 Platform-Global**, **1 Tenant-Root**, **50 Tenant-Owned**, and **2 Cross-Cutting**. Stage 1 RLS covers **13 tables** (1 tenant-root + 12 tenant-owned).                                                                                                                                                      |
| **2**  | **Platform Admin Authorization via Custom GUC** | Used `app.is_platform_admin = 'true'` via custom GUC, allowing potential privilege escalation from tenant sessions.                | **Eliminated `app.is_platform_admin` custom GUC entirely.** Privileged platform operations execute over a separate connection pool authenticated under the dedicated `dcmp_platform_admin` database role (`NOBYPASSRLS`). Customer data access requires executing the `SECURITY DEFINER` function `open_support_session` with active grant validation, cryptographic HMAC transaction signatures, and mandatory audit logging.                               |
| **3**  | **Limits of Tenant Context & RLS**              | RLS was described as if `set_config` independently authenticated the tenant.                                                       | Formally documented that `set_config` is transaction-local context carrier, not an authenticator. RLS is a **defense-in-depth barrier** enforcing context supplied by the application layer. Relational integrity is enforced by composite FKs. Added security integration tests.                                                                                                                                                                            |
| **4**  | **RLS for Tenant-Root `organizations`**         | Missing explicit policy for `organizations` table.                                                                                 | Defined explicit tenant-root policy: `id = current_setting('app.current_organization_id', true)::uuid`. Restricts customer sessions to own organization. Attached engine trigger `trg_prevent_tenant_org_lifecycle_tampering` to block tenant modifications to status or code. Platform lifecycle operations use `dcmp_platform_admin`.                                                                                                                      |
| **5**  | **Migration Database Privileges**               | `dcmp_migrator` had blanket `BYPASSRLS` permission.                                                                                | Removed default `BYPASSRLS` from `dcmp_migrator`. Table ownership is assigned to `dcmp_migrator`, and `FORCE ROW LEVEL SECURITY` binds even table owners during DML. Runtime role `dcmp_app` has strictly DML (`SELECT, INSERT, UPDATE, DELETE`) with `NOBYPASSRLS`.                                                                                                                                                                                         |
| **6**  | **Composite Foreign Key Mapping**               | Incomplete mapping across all tenant child entities.                                                                               | Authored a comprehensive relationship matrix classifying all 50 tenant-owned entities into composite tenant-aware FKs, platform-global FKs, or polymorphic relationships.                                                                                                                                                                                                                                                                                    |
| **7**  | **Checklist Question Version Integrity**        | Undefined version integrity between source and target questions in `question_conditions`.                                          | Enforced version integrity declaratively via composite foreign keys: denormalized `version_id` onto `checklist_questions` (`UNIQUE (organization_id, version_id, id)`), and enforced dual composite FKs sharing `(organization_id, version_id)` in `question_conditions`.                                                                                                                                                                                    |
| **8**  | **Global Permission Catalogue Access**          | Undefined access boundary for `permissions` table.                                                                                 | `dcmp_app` granted read-only `SELECT` on `permissions`. In-memory caching in NestJS service layer prevents repetitive queries; customer APIs cannot query or mutate platform catalogues directly.                                                                                                                                                                                                                                                            |
| **9**  | **Inspection Attempt Uniqueness**               | `UNIQUE (assignment_id, attempt_number)` lacked tenant scoping.                                                                    | Updated to tenant-aware constraint: `UNIQUE (organization_id, assignment_id, attempt_number)` backed by composite FK `(organization_id, assignment_id) REFERENCES checklist_assignments(organization_id, id)`.                                                                                                                                                                                                                                               |
| **10** | **Refresh Token Rotation History & Retries**    | Overwriting `refresh_token_hash` prevented token reuse detection, while one-way hashing conflicted with plaintext retry responses. | Introduced `user_session_tokens` (#11 in Stage 1) with composite replacement FK `(organization_id, session_id, replaced_by_token_id) REFERENCES user_session_tokens (organization_id, session_id, id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`. Flaky mobile retries within 30s are served via a **Client-Bound Transient Encrypted Idempotency Cache in Redis** (AES-256-GCM, 30s TTL). Retrying after 30s triggers instant hard reuse detection. |
| **11** | **AssignmentTarget Semantics**                  | Ambiguity between recurring schedule targets and concrete assignment dispatch.                                                     | Clarified that `ChecklistSchedule` defines recurrence targeting, while `AssignmentTarget` models concrete multi-target dispatching (pools/teams/locations) for generated `ChecklistAssignment` instances.                                                                                                                                                                                                                                                    |

---

## 2. Reconciled 62-Entity Database Architecture

### 2.1 Four-Tier Entity Scoping Summary

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        DCMP 62-Entity Final Scoping Matrix                             │
├──────────────────────┬──────────────────┬──────────────────────┬───────────────────────┤
│ Platform-Global      │ Tenant-Root      │ Tenant-Owned         │ Cross-Cutting         │
│ (9 Tables)           │ (1 Table)        │ (50 Tables)          │ (2 Tables)            │
├──────────────────────┼──────────────────┼──────────────────────┼───────────────────────┤
│ organization_id:     │ id = org_id      │ organization_id:     │ organization_id:      │
│ ABSENT               │ (Primary Key)    │ MANDATORY (UUID)     │ NULLABLE (UUID)       │
├──────────────────────┼──────────────────┼──────────────────────┼───────────────────────┤
│ RLS: NONE            │ RLS: FORCED      │ RLS: FORCED          │ RLS: FORCED           │
│ Access: Platform     │ Access: Own Org  │ Access: Current Org  │ Access: Filtered Org  │
│ Operators Only       │ Only             │ Only via Context     │ or Global Admin       │
└──────────────────────┴──────────────────┴──────────────────────┴───────────────────────┘
```

---

## 3. Privileged Platform Access & Database Role Security Model

### 3.1 Four Distinct PostgreSQL Roles

1. **`dcmp_migrator` (DDL & Schema Owner):**
   - Owns schemas, tables, views, sequences, and functions.
   - Executes `prisma migrate deploy` during CI/CD release pipelines.
   - **Does NOT possess `BYPASSRLS` by default.**
   - All tenant-owned tables execute `ALTER TABLE <name> FORCE ROW LEVEL SECURITY;`. Therefore, even `dcmp_migrator` is subjected to RLS if it executes DML queries against tenant-owned tables.
2. **`dcmp_app` (Tenant Application Runtime Role):**
   - Dedicated role utilized by NestJS Customer Web API, Mobile Sync endpoints, and background BullMQ workers.
   - **Privileges:** `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dcmp_app;`
   - **Strict Restrictions:** Denied `SUPERUSER`, denied `BYPASSRLS`, denied `CREATE`, `ALTER`, `DROP`.
   - **RLS Enforcement:** Always bound by `organization_id = current_setting('app.current_organization_id', true)::uuid`.
   - **Platform-Global Access:** Granted read-only `SELECT` strictly on `permissions`, `license_plans`, `license_plan_entitlements`, and `application_releases`. Denied all access to `platform_admins`, `platform_roles`, and `platform_admin_role_assignments`.
3. **`dcmp_platform_admin` (Privileged Platform Operations Role):**
   - Dedicated role utilized exclusively by the Platform Owner Admin Backend (`apps/platform-admin`).
   - Connects through an **isolated database connection pool** with separate credentials.
   - Granted full management rights over Platform-Global tables (`platform_admins`, `platform_roles`, `organizations`, `license_plans`).
   - Allowed to query Cross-Cutting logs (`platform_admin_audit_logs`, `security_events`) globally.
   - Access to customer business records requires executing the `SECURITY DEFINER` function `open_support_session` with an active, unrevoked grant from `support_access_grants`.
4. **`dcmp_sec_definer` (Dedicated Non-Login Security Function Owner):**
   - Dedicated non-login role owning the `dcmp_security` schema and cryptographic routines (`open_support_session`, `verify_support_signature`).

---

## 4. Comprehensive Database Acceptance & Security Test Suite (24 Scenarios)

The Phase 2.2 implementation must execute and pass the following 24 mandatory integration test suites against an active PostgreSQL 16 container:

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
12. **DB-SEC-012:** Revoking a support grant mid-investigation immediately drops `dcmp_platform_admin` visibility to 0 rows.
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

## 5. Implementation Readiness Sign-Off

All findings have been resolved, and the 62-entity catalogue is mathematically reconciled and validated.

**Phase 2.1 is officially concluded. The architecture is approved for Phase 2.2 Stage 1 implementation.**
