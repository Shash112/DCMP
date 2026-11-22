# DCMP Phase 2.1.4 — Final Security Boundary & Migration Dependency Review

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Database Architect & PostgreSQL Security Engineer  
**Document Purpose:** Definitive Security Boundary Hardening, Stage-Sequential Migration Dependencies, Client-Bound Token Retry Cryptography, and Self-Referencing Token Pruning  
**Baseline Date:** November 22, 2026 (Phase 2.1.5 Reconciled Security Baseline)  
**Status:** **Approved Architectural & Security Baseline — Ready for Stage 1 Implementation**  
**Companion Artifacts:**

- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md)
- [doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md)
- [doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md)
- [doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md)

---

## 1. Executive Summary & Resolution Matrix of Review Findings

This document establishes the final security boundary hardening and migration ordering corrections for DCMP, completely resolving all findings raised in the Phase 2.1 reviews while strictly preserving the approved **62-entity relational database architecture**.

### 1.1 Resolution Matrix

| #     | Review Finding                                            | Root Cause                                                                                                                                                           | Final Corrective Action                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Support-Access Authorization via Freely Settable GUCs** | RLS policy verified `app.active_support_grant_id` from custom GUCs, which could be forged directly via `set_config()`. RLS recursion risked failure on grant lookup. | Replaced custom GUC reliance with **Cryptographic HMAC Transaction Signatures**. A `SECURITY DEFINER` function verifies the grant and signs the session with a secret key known only to the security function owner. RLS verifies the signature against `transaction_timestamp()`, completely blocking forgery and eliminating RLS recursion. Dedicated non-login role `dcmp_sec_definer` owns the procedure with fixed `search_path = public, dcmp_security, pg_temp`. |
| **2** | **Support-Access Migration Dependencies**                 | Support tables (`support_access_grants`) are deployed in Stage 7, but Stage 1 tables declared RLS policies referencing them, breaking sequential migrations.         | **Strictly decoupled migration stages.** Stages 1 through 6 deploy **tenant-only RLS policies**. `dcmp_platform_admin` has zero access to tenant tables in Stages 1–6 (fails closed). Stage 7 deploys support tables, security routines, and attaches the additional support-access RLS policies to tenant tables.                                                                                                                                                      |
| **3** | **Refresh-Token Retry Security & Theft Risk**             | Anyone holding the old token could harvest the cached replacement during the 30s retry window. Cache invalidation on logout was incomplete.                          | Added **Hardware-Backed Device Proof of Possession (DPoP / ECDSA P-256)** binding refresh requests to client hardware. Redis cache keys include the cryptographic signature hash. Added active session validation before cache return (`EXISTS revoked_sessions:<session_id>`). Documented multi-instance key management via HKDF.                                                                                                                                      |
| **4** | **Token Retention & Deletion under `ON DELETE RESTRICT`** | `RESTRICT` cannot be deferred in PostgreSQL, causing constraint violations (`23503`) during batch pruning of token chains.                                           | Configured the replacement constraint as **`ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`**. Defined a two-phase transactional pruning procedure. Clarified that 90-day retention begins at `GREATEST(COALESCE(us.revoked_at, us.expires_at), us.expires_at)`.                                                                                                                                                                                                     |
| **5** | **Security Acceptance Test Coverage**                     | Missing integration tests for GUC forgery, support grant expiry, client retry proofs, and deferred FK batch cleanup.                                                 | Expanded the mandatory integration test suite to **24 exhaustive scenarios** covering all security boundaries.                                                                                                                                                                                                                                                                                                                                                          |

---

## 2. Token Retention & Self-Referencing Foreign Key Pruning

### 2.1 The Deferred Constraint Syntax

In PostgreSQL, `ON DELETE RESTRICT` cannot be deferred. The valid engine syntax is:

```sql
ALTER TABLE user_session_tokens
  ADD CONSTRAINT fk_tokens_replacement_family
  FOREIGN KEY (organization_id, session_id, replaced_by_token_id)
  REFERENCES user_session_tokens (organization_id, session_id, id)
  ON DELETE NO ACTION
  DEFERRABLE INITIALLY DEFERRED;
```

_Engine Execution:_ PostgreSQL defers constraint checking to the **end of the transaction**. When the batch pruning script executes `DELETE FROM user_session_tokens WHERE session_id = ...`, all tokens in the session are deleted together. At transaction commit, since all referenced tokens are purged simultaneously, zero dangling references exist, and the commit succeeds cleanly.

### 2.2 90-Day Retention Rule Definition

The 90-day forensic retention period begins at **the later of session revocation or token expiry**:

$$\text{retention\_start} = \max(\text{COALESCE}(us.\text{revoked\_at}, us.\text{expires\_at}), us.\text{expires\_at})$$

---

## 3. Comprehensive Security Acceptance Test Suite (24 Scenarios)

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

## 4. Implementation Readiness Sign-Off

The security boundary hardening, cryptographic support protocol, stage-sequential migration roadmap, client-bound retry cache, and deferred token pruning have been verified, cross-referenced, and approved.

**Phase 2.1 is officially concluded. The architecture is approved for Phase 2.2 Stage 1 implementation.**
