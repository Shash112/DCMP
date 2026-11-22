# DCMP Architectural Decision Register (ADR) — Database Architecture Baseline

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Database Architect, PostgreSQL Security Engineer & Prisma Technical Lead  
**Document Purpose:** Authoritative Record of Database, Tenant-Isolation, Security, and Prisma Schema Decisions  
**Status:** **Phase 2.1.12 Baseline — APPROVED FOR POSTGRESQL 16 VALIDATION — NOT approved for Phase 2.2 implementation**  
**Date:** November 22, 2026  
**Companion Artifacts:**

- [doc/PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md](PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md) — **authoritative Corrections A–F**
- [doc/PHASE_2_1_11_FINAL_SECURITY_OWNERSHIP_AND_IDEMPOTENCY_REVIEW.md](PHASE_2_1_11_FINAL_SECURITY_OWNERSHIP_AND_IDEMPOTENCY_REVIEW.md) — superseded where contradictory
- [doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md](PHASE_2_1_DATABASE_DESIGN_REVIEW.md)
- [doc/PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md](PHASE_2_1_2_FINAL_ARCHITECTURAL_REVIEW.md)
- [doc/PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md](PHASE_2_1_3_FINAL_SECURITY_READINESS_REVIEW.md)
- [doc/PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md](PHASE_2_1_4_FINAL_SECURITY_BOUNDARY_REVIEW.md)
- [doc/PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md](PHASE_2_1_5_POSTGRESQL_SECURITY_FINAL_REVIEW.md)
- [doc/PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md](PHASE_2_1_6_FINAL_IDENTITY_AND_TRANSACTION_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md](PHASE_2_1_7_FINAL_CRYPTOGRAPHIC_AND_CONCURRENCY_REVIEW.md)
- [doc/PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md](PHASE_2_1_8_FINAL_SQL_DPOP_AND_REVOCATION_REVIEW.md)
- [doc/PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md](PHASE_2_1_9_FINAL_RLS_DPOP_AND_AUDIT_SECURITY_REVIEW.md)
- [doc/PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md](PHASE_2_1_10_FINAL_POSTGRESQL_POLICY_AND_SUPPORT_REPLAY_REVIEW.md) — superseded where contradictory

---

## 1. Summary of Architectural Decisions

| Decision ID | Title                                                                                 | Status                       | Category                              | Target Migration        |
| ----------- | ------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------------- | ----------------------- |
| **ADR-001** | Staged Row-Level Security (RLS) Rollout & Context Boundary                            | **Decided**                  | Security & Multi-Tenancy              | Stage 1 through Stage 7 |
| **ADR-002** | Composite Tenant-Aware Foreign Keys & Relational Isolation                            | **Decided**                  | Relational Integrity                  | Stage 1 through Stage 7 |
| **ADR-003** | Four-Tier Entity Ownership Scoping (63 Entities)                                      | **Decided (Revised 2.1.12)** | Data Governance                       | All Stages              |
| **ADR-004** | Prisma Multi-File Schema Structure (`prismaSchemaFolder`)                             | **Decided**                  | Toolchain & ORM                       | Stage 1 Foundation      |
| **ADR-005** | Dual-Tier Session Persistence & Refresh-Token History (`user_session_tokens`)         | **Decided**                  | Identity & Security                   | Stage 1 Foundation      |
| **ADR-006** | Assignment Recurrence, Execution Attempts & Multi-Target Dispatch                     | **Decided**                  | Domain Semantics                      | Stage 4 & Stage 5       |
| **ADR-007** | Partial Unique Indexes for Soft-Delete Handling                                       | **Decided**                  | Engine Constraints                    | Stages 1, 2, 3, 5, 6    |
| **ADR-008** | Multi-Tier Database Roles & Least-Privilege Grants                                    | **Decided**                  | Infrastructure Security               | Stage 1 Foundation      |
| **ADR-009** | Cryptographic Support-Access Authorization (HMAC Signatures & Mid-Session Revocation) | **Decided (Revised 2.1.11)** | Platform Security                     | Stage 7 Hardening       |
| **ADR-010** | Declarative Checklist Question Version Integrity                                      | **Decided**                  | Relational Integrity                  | Stage 3 Templates       |
| **ADR-011** | Client-Bound Idempotent Token Retry Cache & Replay Protection                         | **Decided (Revised 2.1.12)** | Cryptographic Security                | Stage 1 Foundation      |
| **ADR-012** | Organization Lifecycle Authorization & Tamper Prevention Trigger                      | **Decided (Revised 2.1.11)** | Schema & Engine Security              | Stage 1 Foundation      |
| **ADR-013** | Stage-Decoupled RLS Policy Deployment                                                 | **Decided**                  | Migration Architecture                | Stages 1–6 vs Stage 7   |
| **ADR-014** | Deferrable NO ACTION Token Replacement FK & 90-Day Retention                          | **Decided**                  | Engine Constraints & Retention        | Stage 1 Foundation      |
| **ADR-015** | Hardware-Backed Device Proof-of-Possession (DPoP / ECDSA P-256)                       | **Decided**                  | Identity & Device Binding             | Stage 1 & Stage 2       |
| **ADR-016** | Non-Login SECURITY DEFINER Role (`dcmp_sec_definer`) & Schema Isolation               | **Decided (Revised 2.1.11)** | PostgreSQL Security                   | Stage 7 Hardening       |
| **ADR-017** | Standard DPoP Protocol (RFC 9449) & Denial-of-Service Prevention                      | **Decided**                  | Authentication Architecture           | Stage 1 Foundation      |
| **ADR-018** | Cryptographic Signed Support Assertions (SSA) & Transaction Isolation                 | **Decided**                  | Privileged Access Security            | Stage 7 Hardening       |
| **ADR-019** | Authoritative Redis Outage, DB Session State Verification & Distributed Lock Protocol | **Decided (Revised 2.1.12)** | Distributed Systems & Concurrency     | Stage 1 Foundation      |
| **ADR-020** | Durable Security Audit Logging & Statement-Timestamp Expiry Semantics                 | **Decided**                  | Security & Observability              | Stage 7 Hardening       |
| **ADR-021** | Blind Audit-Writer Boundary & Linearized Revocation Protocol                          | **Decided (Revised 2.1.12)** | Infrastructure Security & Concurrency | Stage 1 & Stage 7       |
| **ADR-022** | Retry-Aware DPoP Nonce Protocol & Composite Idempotency Ordering                      | **Decided (Revised 2.1.12)** | Authentication Architecture           | Stage 1 Foundation      |
| **ADR-023** | Constant-Time Cryptographic Limits & PostgreSQL LEAKPROOF Semantics                   | **Decided**                  | Cryptographic Security                | Stage 7 Hardening       |
| **ADR-024** | Hardened Audit-Writer Boundary, FORCE RLS & Nullable Organization Attribution         | **Decided**                  | Security & Observability              | Stage 1 Foundation      |
| **ADR-025** | Dual-Tier Permissive & Restrictive RLS Policy Composition                             | **Decided**                  | Security & Multi-Tenancy              | Stage 1 through Stage 7 |
| **ADR-026** | Single-Use Challenge & Transaction-Bound Support Authorization                        | **Decided**                  | Platform Security                     | Stage 7 Hardening       |
| **ADR-027** | Dedicated Statement TRUNCATE Trigger & In-Flight DPoP Concurrency Serialization       | **Decided (Revised 2.1.12)** | Observability & Concurrency           | Stage 1 Foundation      |
| **ADR-028** | PostgreSQL-Backed Refresh Idempotency Records (`refresh_idempotency_records`)         | **Decided**                  | Authentication & Durability           | Stage 1 Foundation      |
| **ADR-029** | Organization Lifecycle Column-Level Privileges & Trigger Guard                        | **Decided**                  | Schema & Engine Security              | Stage 1 Foundation      |
| **ADR-030** | Path-Preserving Canonical Retry-Key Encoding with Verified Digests                    | **Decided**                  | Cryptographic Security                | Stage 1 Foundation      |

---

## 2. Detailed Decision Records

---

### ADR-001: Staged Row-Level Security (RLS) Rollout & Context Boundary

- **Context:**
  - DCMP operates on a shared PostgreSQL 16 database and shared schema across multiple customer organizations.
  - Relying on custom GUCs for platform administrator bypass introduces severe privilege escalation risks.
- **Options Considered:**
  - _Option A: Defer RLS to Stage 7 (Rejected)._ Unacceptable big-bang regression risk.
  - _Option B: Custom GUC for Admin Bypass (Rejected)._ Any session under `dcmp_app` could execute `SELECT set_config('app.is_platform_admin', 'true', false)` to bypass RLS.
  - _Option C: Staged RLS Rollout with Dedicated Privileged Role & Context Clarification (Selected)._ Deploy RLS policies alongside tables in every migration stage (Stages 1–7). Use transaction-local `set_config('app.current_organization_id', :orgId, true)`.
- **Decision:**
  - Adopt **Option C**.
  - **Limits of Tenant Context:** Transaction-local `set_config` prevents connection-pool context leakage across transactions, but does not independently authenticate the caller. The application layer (NestJS AuthGuard) is the primary authentication authority; PostgreSQL RLS is a **defense-in-depth safety net** enforcing the context supplied by the application.
  - **Tenant-Root Entity Policy (`organizations`):** Enforce explicit RLS:
    `USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)`.
    Customer sessions can only query their own organization row. Lifecycle operations (create, suspend, delete organizations) use `dcmp_platform_admin`.
  - **Tenant-Owned Entities Policy:** Enforce `organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid`.
  - **Stage 1 Scope:** RLS is applied immediately to **13 tables** (1 tenant-root + 12 tenant-owned).
- **Justification:**
  - Eliminates custom GUC privilege escalation vectors.
  - Continuous verification: Tenant isolation is enforced from the first migration.

---

### ADR-002: Composite Tenant-Aware Foreign Keys & Relational Isolation

- **Context:**
  - In a shared multi-tenant database, standard single-column foreign keys reference only `id`.
  - If application logic accidentally links Tenant A's inspection to Tenant B's asset, a standard foreign key allows the relation, causing cross-tenant corruption.
- **Options Considered:**
  - _Option A: Application-level validation only (Rejected)._ Vulnerable to developer error, batch jobs, and direct mutations.
  - _Option B: Composite Tenant-Aware Foreign Keys (Selected)._ Parent tables declare `UNIQUE (organization_id, id)`. Child tables include `organization_id UUID NOT NULL` and enforce `FOREIGN KEY (organization_id, parent_id) REFERENCES parent_table (organization_id, id)`.
- **Decision:**
  - Adopt **Option B** across all 50 tenant-owned relationships.
- **Justification:**
  - Enforces relational isolation at the database engine level. Cross-tenant references trigger foreign key violations (`23503`).
  - Supported natively in Prisma ORM via `@@unique([organizationId, id])` and multi-column `@relation`.

---

### ADR-003: Four-Tier Entity Ownership Scoping (63 Entities)

- **Context:**
  - The database contains entities with differing lifecycles and isolation requirements.
  - Reconciling the inventory and introducing `user_session_tokens` establishes a definitive entity count.
- **Options Considered:**
  - _Option A: Binary Scope (Tenant vs Global) (Rejected)._ Inadequate for cross-cutting audit logs and the tenant root.
  - _Option B: Four-Tier Scope Hierarchy (Selected)._
- **Decision:**
  - Adopt **Option B** with the following authoritative counts:
    1. **Platform-Global (9 tables):** `platform_admins`, `platform_roles`, `platform_permissions`, `platform_admin_role_assignments`, `platform_role_permissions`, `permissions`, `license_plans`, `license_plan_entitlements`, `application_releases`. Managed by platform operators. `organization_id` is absent.
    2. **Tenant-Root (1 table):** `organizations`. Root tenant record. Primary key `id` is the tenant identifier.
    3. **Tenant-Owned (51 tables):** Customer operational entities including `user_session_tokens` and Phase 2.1.12 `refresh_idempotency_records`. `organization_id UUID NOT NULL` mandatory.
    4. **Cross-Cutting (2 tables):** `platform_admin_audit_logs`, `security_events`. `organization_id UUID NULL`. Accessible globally to platform operators via `dcmp_platform_admin`, and filtered conditionally to tenants via RLS (`organization_id = current_org_id`).
    - **Total Entities:** Exactly **63 models** (Phase 2.1.12).
- **Justification:**
  - Complete reconciliation across inventories, diagrams, and migration stages; entity #63 justified by durable refresh recovery (ADR-028).

---

### ADR-004: Prisma Multi-File Schema Structure (`prismaSchemaFolder`)

- **Context:**
  - Modeling 63 entities in a single `schema.prisma` file creates a monolithic file exceeding 2,500 lines, causing merge conflicts and maintenance friction.
- **Options Considered:**
  - _Option A: Single Monolithic `schema.prisma` (Rejected as primary)._ High merge conflict risk.
  - _Option B: Third-Party Stitching CLI (Rejected)._ Fragile external dependencies.
  - _Option C: Native Prisma Multi-File Schema (`prismaSchemaFolder`) (Selected)._ Available in Prisma >= 5.15.0 and GA in Prisma 6.x.
- **Decision:**
  - Adopt **Option C**.
  - Package location: `packages/database/prisma/schema/`.
  - Organized by domain and migration stage: `_base.prisma`, `01_platform.prisma`, `02_identity.prisma`, `03_checklists.prisma`, etc.
- **Justification:**
  - Zero third-party build dependencies. Full native support by Prisma CLI.

---

### ADR-005: Dual-Tier Session Persistence & Refresh-Token History (`user_session_tokens`)

- **Context:**
  - Overwriting `refresh_token_hash` on each rotation loses historical token hashes, making token reuse detection impossible.
- **Options Considered:**
  - _Option A: Single Overwritten Token Hash in `user_sessions` (Rejected)._ Prevents token reuse detection; violates RFC 6819.
  - _Option B: Dedicated `user_session_tokens` Table with Full Token History (Selected)._
- **Decision:**
  - Adopt **Option B**. Add entity #11: `user_session_tokens` (Tenant-Owned, Stage 1).
  - Schema includes: `id`, `organization_id`, `session_id`, `token_hash VARCHAR(64) NOT NULL UNIQUE`, `sequence_number`, `created_at`, `expires_at`, `consumed_at`, `revoked_at`, `replaced_by_token_id`.
  - **Relational Integrity for Replacement:** Enforce composite foreign key:
    `FOREIGN KEY (organization_id, session_id, replaced_by_token_id) REFERENCES user_session_tokens (organization_id, session_id, id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`.
  - **Cryptographic Security:** Refresh tokens are hashed using SHA-256 before storage; plaintext tokens are never stored.
  - **Unambiguous Revocation SQL:** Session revocation uses explicitly aliased columns:
    `WHERE us.id = p_session_id AND us.organization_id = p_organization_id;`.
  - **Forensic Retention:** Consumed tokens retained for 90 days past `GREATEST(COALESCE(revoked_at, expires_at), expires_at)` for security investigation before pruning.
- **Justification:**
  - Full compliance with NIST SP 800-63B and RFC 6819. Guaranteed breach containment upon token theft.

---

### ADR-006: Assignment Recurrence, Execution Attempts & Multi-Target Dispatch

- **Context:**
  - Ambiguity existed between schedule recurrence definitions, concrete assignment dispatch, multi-target assignment pools, and repeat inspection attempts.
- **Options Considered:**
  - _Option A: Single Assignment Overwritten on Re-inspection (Rejected)._ Destroys audit history and inspection rejection evidence.
  - _Option B: Normalized Architecture with Tenant-Aware Uniqueness (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - **Recurrence:** `ChecklistSchedule` stores recurrence rules (cron, frequency interval).
  - **Concrete Dispatch:** `ChecklistAssignment` represents a concrete task instance generated for a specific due-date window.
  - **Multi-Target Dispatch (`AssignmentTarget`):** Models multi-target dispatching when an assignment applies to a pool (multiple users, team, department, or location). Uses exclusive composite foreign keys with `CHECK (num_nonnulls(target_user_id, target_team_id, target_department_id, target_location_id) = 1)` to guarantee type safety and same-tenant integrity.
  - **Execution Attempts:** `InspectionInstance` represents an execution attempt.
    Enforce tenant-aware uniqueness: `UNIQUE (organization_id, assignment_id, attempt_number)` with composite foreign key `FOREIGN KEY (organization_id, assignment_id) REFERENCES checklist_assignments (organization_id, id) ON DELETE RESTRICT`.
- **Justification:**
  - Full re-inspection auditability. Strict tenant-aware relational integrity.

---

### ADR-007: Partial Unique Indexes for Soft-Delete Handling

- **Context:**
  - Entities with natural uniqueness constraints (e.g. `lower(email)` in `users`, `code` in `checklist_templates`) conflict with soft-deletion (`deleted_at IS NOT NULL`).
- **Options Considered:**
  - _Option A: Hard delete records (Rejected)._ Destroys audit compliance.
  - _Option B: Unconditional Prisma unique constraints (Rejected)._ Prevents re-creating deleted accounts.
  - _Option C: PostgreSQL Partial Unique Indexes in SQL companion files (Selected)._
- **Decision:**
  - Adopt **Option C**.
  - Omit unconditional `@unique` on soft-deletable fields in Prisma.
  - Create partial indexes: `CREATE UNIQUE INDEX uq_users_org_email_active ON users (organization_id, lower(email)) WHERE deleted_at IS NULL;`.
- **Justification:**
  - Standard enterprise soft-delete pattern; preserves historical integrity.

---

### ADR-008: Multi-Tier Database Roles & Least-Privilege Grants

- **Context:**
  - Running application queries as a PostgreSQL superuser or table owner automatically bypasses Row-Level Security.
  - Granting `BYPASSRLS` to migration roles creates security risks during maintenance scripts.
- **Options Considered:**
  - _Option A: Single Database User (Rejected)._ Bypasses RLS entirely.
  - _Option B: Three-Tier Role Separation (Selected)._
- **Decision:**
  - Adopt **Option B: Three-Tier Role Separation**:
    1. **`dcmp_migrator` (DDL & Schema Owner):** Owns schemas and tables. Executes migrations. Does NOT have `BYPASSRLS`. Tables declare `FORCE ROW LEVEL SECURITY`, binding even table owners during DML.
    2. **`dcmp_app` (Tenant Application Role):** Used by Customer Web, Mobile Sync, and BullMQ workers. Granted `SELECT, INSERT, UPDATE, DELETE` only. Explicitly `NOSUPERUSER` and `NOBYPASSRLS`. Bounded by RLS.
    3. **`dcmp_platform_admin` (Privileged Management Role):** Used exclusively by the Platform Admin backend over an isolated connection pool. Manages Platform-Global entities and audits.
- **Justification:**
  - Enforces least privilege. Prevents accidental RLS bypasses in application code or migrations.

---

### ADR-009: Cryptographic Support-Access Authorization (HMAC Signatures & Mid-Session Revocation)

- **Context:**
  - Relying on custom GUCs (`app.active_support_grant_id`) creates forgery risks, while subqueries on tenant tables inside RLS policies create RLS recursion.
  - If a support grant is revoked or expires mid-investigation, access must drop immediately.
  - Historical proposal in Phase 2.1.4/2.1.5 used `transaction_timestamp()`, which remained frozen for the transaction duration and created a snapshot vulnerability against mid-transaction grant expiration.
- **Options Considered:**
  - _Option A: Raw GUC Matching in RLS Policy (Rejected)._ Vulnerable to direct `set_config()` forgery by `dcmp_platform_admin`.
  - _Option B: Cryptographic HMAC Transaction Signature with Live Grant State Check (Selected; Revised in Phase 2.1.8)._
- **Decision:**
  - Adopt **Option B**.
  - Create dedicated non-login role `dcmp_sec_definer` and isolated schema `dcmp_security`.
  - Function `open_support_session(TEXT, UUID, UUID, UUID)` validates Compact JWT SSA, consumes single-use `jti` and challenge, computes a transaction-bound HMAC (`txid_current()`), and sets transaction-local GUCs including `app.support_signature`.
  - Function `verify_support_signature()` (no args; reads GUCs) verifies HMAC AND re-checks `revoked_at IS NULL AND expires_at > statement_timestamp()` without RLS recursion.
  - **Phase 2.1.11:** Both functions `OWNER TO dcmp_sec_definer`. `dcmp_platform_admin` **must** hold `EXECUTE` on `verify_support_signature()` because RLS policy expressions run with caller privileges. Revoking EXECUTE from the querying role breaks support access.
  - Support sessions execute under `READ COMMITTED` with `statement_timeout = '15s'` and `idle_in_transaction_session_timeout = '30s'`.
  - Durable audit logging to `security_events` uses a separate audit connection (ADR-020/021), not the aborted support transaction.
- **Justification:**
  - Eliminates GUC forgery and RLS recursion without granting `BYPASSRLS`. Fail-closed on revoke/expiry. EXECUTE grants must match how PostgreSQL evaluates policy expressions.

---

### ADR-010: Declarative Checklist Question Version Integrity

- **Context:**
  - `question_conditions` establishes conditional logic between a `source_question_id` and a `target_question_id`.
  - If constraints reference only `checklist_questions(id)`, conditions could cross checklist versions (e.g. source question from v1, target from v2), corrupting template execution.
- **Options Considered:**
  - _Option A: Procedural PostgreSQL Trigger (Rejected as primary)._ Adds trigger execution overhead and potential race conditions.
  - _Option B: Declarative Composite Foreign Keys (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Denormalize `version_id UUID NOT NULL` onto `checklist_questions`.
  - Add natural composite unique constraint: `UNIQUE (organization_id, version_id, id)` on `checklist_questions`.
  - In `question_conditions`, include `version_id UUID NOT NULL` and enforce dual composite foreign keys:
    ```sql
    FOREIGN KEY (organization_id, version_id, source_question_id)
      REFERENCES checklist_questions (organization_id, version_id, id) ON DELETE CASCADE;
    FOREIGN KEY (organization_id, version_id, target_question_id)
      REFERENCES checklist_questions (organization_id, version_id, id) ON DELETE CASCADE;
    ```
- **Justification:**
  - Mathematical impossibility of cross-version condition corruption enforced declaratively by the PostgreSQL engine.

---

### ADR-011: Client-Bound Idempotent Token Retry Cache & Replay Protection

- **Context:**
  - Storing only one-way SHA-256 hashes prevents plaintext recovery during network retries.
  - Caching replacement tokens by hash alone allows bearer token interception attacks during the 30-second window.
- **Options Considered:**
  - _Option A: Store Plaintext in DB (Rejected)._ Severe security risk.
  - _Option B: Client-Bound Transient Encrypted Idempotency Cache in Redis (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Refresh requests require cryptographic DPoP signatures from client hardware keystore.
  - Redis key: `auth:retry:` ‖ `dcmp-retry-key-v1` SHA-256 hex (optional 30s cache).
  - **Phase 2.1.12:** Durable twin in PostgreSQL `refresh_idempotency_records` (60s TTL, AES-256-GCM ciphertext, Vault key outside DB) — ADR-028.
  - Identical proof within TTL recovers via Redis or PostgreSQL after session-active check.
  - Stolen token without valid DPoP / different proof on consumed token → hard reuse revocation.
  - Logout invalidates Redis keys and sets `invalidated_at` on idempotency rows.
- **Justification:**
  - Mobile retry durability without plaintext token storage or Redis correctness dependence.

---

### ADR-012: Organization Lifecycle Authorization & Tamper Prevention Trigger

- **Context:**
  - Customer tenant runtime sessions (`dcmp_app`) must be permitted to view and customize their organization profile, but must be strictly blocked from altering subscription status, organization code, or soft-delete markers.
  - Phase 2.1.10 specified `platform_admin_org_lifecycle_permissive FOR ALL USING (true) WITH CHECK (true)`, which conflates org lifecycle administration with unrestricted org-row access messaging and risks being misread as tenant business-data authorization.
- **Options Considered:**
  - _Option A: Application-Level Service Checks Only (Rejected)._ Vulnerable to route omissions or ORM bypass.
  - _Option B: Database-Level Trigger Enforcement (Selected; Revised Phase 2.1.11)._
- **Decision:**
  - Adopt **Option B** with Phase 2.1.11 command scoping.
  - Customer role `dcmp_app` is denied `INSERT` and `DELETE` on `organizations`.
  - Attach a `BEFORE UPDATE` trigger on `organizations` raising `42501` if `CURRENT_USER = 'dcmp_app'` and changes touch `status`, `org_code`, `id`, or `deleted_at`.
  - `dcmp_platform_admin` receives **command-scoped** policies plus **column-level `GRANT UPDATE (status, suspended_at, suspended_reason, deleted_at, updated_at)`** (ADR-029). Hard DELETE denied for runtime roles.
  - Platform org lifecycle policies **do not** authorize tenant-owned business-data access; that requires support HMAC (`verify_support_signature`).
- **Justification:**
  - Separates SaaS lifecycle administration from customer data support access while retaining engine-enforced tamper prevention and column least privilege.

---

### ADR-013: Stage-Decoupled RLS Policy Deployment

- **Context:**
  - Support tables (`support_access_grants`) are scheduled for Stage 7 deployment.
  - Creating support RLS policies in Stages 1–6 introduces illegal forward dependencies on non-existent tables.
- **Options Considered:**
  - _Option A: Move Support Infrastructure to Stage 1 (Rejected)._ Unnecessarily pulls complex support tables into the core foundation.
  - _Option B: Stage-Decoupled Policy Deployment (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Stages 1–6 deploy **tenant-only RLS policies**. `dcmp_platform_admin` has zero access to tenant tables (fails closed under `FORCE ROW LEVEL SECURITY`).
  - Stage 7 deploys support infrastructure and executes a companion migration that attaches `platform_admin_support_read_policy` across all tenant tables.
- **Justification:**
  - Guarantees 100% clean, linear migration execution with zero forward dependencies.

---

### ADR-014: Deferrable NO ACTION Token Replacement FK & 90-Day Retention

- **Context:**
  - In PostgreSQL, `ON DELETE RESTRICT` cannot be deferred and enforces immediate checking at the statement level.
  - Batch pruning of self-referencing token chains (`T1 -> T2 -> T3`) fails with `23503` under immediate checking.
- **Options Considered:**
  - _Option A: ON DELETE RESTRICT DEFERRABLE (Rejected)._ Invalid syntax in PostgreSQL.
  - _Option B: ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Declare `fk_tokens_replacement_family` as `ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`.
  - Batch pruning deletes all tokens in a session inside a single transaction, validating constraints at `COMMIT`.
  - Partial-chain deletion is strictly rejected by the engine at `COMMIT`.
  - 90-day retention begins at `GREATEST(COALESCE(us.revoked_at, us.expires_at), us.expires_at)`.
- **Justification:**
  - Valid PostgreSQL engine syntax; guarantees atomic complete-chain cleanup while preventing broken token chains.

---

### ADR-015: Hardware-Backed Device Proof-of-Possession (DPoP / ECDSA P-256)

- **Context:**
  - Transmitting static installation IDs and idempotency tokens over HTTP is vulnerable to proxy or TLS-termination interception.
- **Options Considered:**
  - _Option A: Transmitted Static Idempotency Keys (Rejected as standalone)._ Inadequate against transport interception.
  - _Option B: Hardware-Backed Asymmetric Proof of Possession (DPoP) (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Client device generates an asymmetric key pair (ECDSA P-256) inside hardware keystore (Android Keystore / iOS Secure Enclave).
  - Private key never leaves the device. Public key is bound to the session at activation.
  - Every `/auth/refresh` request is signed using the private key.
  - Stolen bearer refresh tokens fail signature verification immediately.
- **Justification:**
  - Elevates DCMP token security to enterprise zero-trust standards.

---

### ADR-016: Non-Login SECURITY DEFINER Role (`dcmp_sec_definer`) & Schema Isolation

- **Context:**
  - Executing `SECURITY DEFINER` functions under login accounts or superusers creates search-path and privilege escalation risks.
  - Phase 2.1.10 omitted mandatory `ALTER FUNCTION ... OWNER TO` and incorrectly revoked `EXECUTE` on `verify_support_signature()` from the RLS calling role.
- **Options Considered:**
  - _Option A: Table Owner or Superuser Ownership (Rejected)._ Excessive privileges and RLS bypass risk.
  - _Option B: Dedicated NOLOGIN Routine Owner with Schema Isolation (Selected; Revised Phase 2.1.11)._
- **Decision:**
  - Adopt **Option B** with Phase 2.1.11 ownership/EXECUTE rules.
  - Provision `dcmp_sec_definer` as `NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOINHERIT`.
  - After `CREATE FUNCTION`, run `ALTER FUNCTION ... OWNER TO dcmp_sec_definer` for open/verify/helpers (SECURITY DEFINER executes as **owner**).
  - Pin `SET search_path = pg_catalog, dcmp_security, public, pg_temp;`.
  - Under `FORCE RLS`, grant least-privilege table rights + permissive policies only for tables the definer must read/write.
  - `REVOKE ALL ON FUNCTION ... FROM PUBLIC` using exact signatures.
  - `GRANT EXECUTE` on `open_support_session(TEXT, UUID, UUID, UUID)` and `verify_support_signature()` to `dcmp_platform_admin` (RLS callers need EXECUTE).
  - Never grant runtime role membership in `dcmp_sec_definer`; `SET ROLE` must fail.
- **Justification:**
  - Matches PostgreSQL ownership and RLS evaluation semantics without broad privilege grants.

---

### ADR-017: Standard DPoP Protocol (RFC 9449) & Denial-of-Service Prevention

- **Context:**
  - Custom heuristics for token binding create security ambiguities and vulnerability to forced-logout Denial-of-Service (DoS) attacks if invalid proofs trigger session revocation.
- **Options Considered:**
  - _Option A: Automatic Session Revocation on Any Invalid Proof (Rejected)._ Allows an attacker with a sniffed token to forge invalid proofs and force logout legitimate users.
  - _Option B: Standard DPoP (RFC 9449) with Strict Proof/Replay Separation (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Adhere strictly to RFC 9449: `dpop+jwt`, `ES256`, `jti`, `htm`, `htu`, `iat`, `nonce`.
  - Invalid proof returns `401 Unauthorized` without revoking the legitimate user's session.
  - Session-family revocation is triggered **only** when a validly signed proof is presented with an already-consumed refresh token outside the retry window.
- **Justification:**
  - Standard compliance; eliminates forced-logout DoS vectors while preserving strict breach containment.

---

### ADR-018: Cryptographic Signed Support Assertions (SSA) & Transaction Isolation

- **Context:**
  - Passing unverified administrator IDs to support routines creates identity spoofing risks.
  - Running support sessions under `REPEATABLE READ` creates snapshot traps where external grant revocations are ignored.
- **Options Considered:**
  - _Option A: Unverified Caller Arguments & REPEATABLE READ (Rejected)._ Vulnerable to identity spoofing and stale access.
  - _Option B: Signed Support Assertions & READ COMMITTED Isolation (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Platform Admin Gateway issues an ephemeral HMAC-signed assertion containing verified claims (`sub`, `req_id`, `grant_id`, `org_id`, `jti`, `exp`).
  - Routine `open_support_session` verifies the signature directly, extracts verified identity, and binds session.
  - Support sessions run under `READ COMMITTED` with `statement_timeout = '15s'`, guaranteeing immediate fail-closed behavior upon mid-session grant revocation.
- **Justification:**
  - Eliminates administrative identity spoofing and guarantees immediate enforcement of customer grant revocations.

---

### ADR-019: Authoritative Redis Outage, DB Session State Verification & Distributed Lock Protocol

- **Context:**
  - Depending on Redis as an authoritative state store risks returning revoked credentials if cache invalidation fails or if Redis experiences cluster failover/outage.
  - Concurrent mobile refresh retries risk token generation race conditions if distributed locks fail or expire.
- **Options Considered:**
  - _Option A: Redis as Co-Authoritative Store with Optimistic Consistency (Rejected)._ Stale tokens may be returned after database-committed logout if cache eviction drops.
  - _Option B: Authoritative PostgreSQL Engine with Mandatory DB Verification & Optional Redlock (Selected; Revised Phase 2.1.11)._
- **Decision:**
  - Adopt **Option B** with Phase 2.1.11 honesty bounds.
  - PostgreSQL is the sole authoritative correctness and serialization boundary.
  - Every Redis cache hit on `/auth/refresh` must `SELECT ... FOR SHARE` / check `user_sessions.is_active` and **COMMIT that check** before returning credentials.
  - **Superseded claim:** “zero stale-credential window.” An in-flight HTTP response after DB authorization remains possible (ADR-021).
  - Redlock optimizes waiting only; it is **not** the security correctness barrier.
  - Conditional `UPDATE user_session_tokens ... WHERE consumed_at IS NULL RETURNING id` is the mandatory rotation barrier.
  - **Phase 2.1.12 (ADR-028):** After rotation, persist AES-256-GCM ciphertext in `refresh_idempotency_records`. PG commit + Redis cache-write failure → identical-proof retry recovers from PostgreSQL within TTL. Different proofs on consumed tokens still revoke.
- **Justification:**
  - PostgreSQL remains authoritative for rotation and legitimate retry recovery without treating Redis as a correctness dependency.

---

### ADR-020: Durable Security Audit Logging & Statement-Timestamp Expiry Semantics

- **Context:**
  - In PostgreSQL, raising an exception aborts the transaction, rolling back any audit records inserted within that transaction and destroying evidence of unauthorized support access attempts.
  - `transaction_timestamp()` remains frozen throughout a transaction, allowing expired grants to appear valid in long-running support transactions.
- **Options Considered:**
  - _Option A: In-Transaction Audit Logging with transaction_timestamp() (Rejected)._ Forensic logs are lost on abort, and expired grants are erroneously treated as active.
  - _Option B: Two-Boundary Gateway Durable Logging & statement_timestamp() Verification (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - The Platform Admin Gateway catches database authorization exceptions (`28000`) and durably writes tamper-evident audit records to `security_events` over an independent, dedicated audit connection that commits unconditionally.
  - Audit records link to tickets via `correlation_id` and strictly exclude customer payloads and sensitive keys.
  - All support grant validation routines and RLS policies evaluate **`statement_timestamp()`** (or `clock_timestamp()`), ensuring that any grant expiring mid-transaction is instantly detected on the subsequent SQL statement and blocked.
- **Justification:**
  - Eliminates forensic audit loss upon transaction abort and closes the mid-transaction grant expiry snapshot vulnerability.

---

### ADR-021: Blind Audit-Writer Boundary & Linearized Revocation Protocol

- **Context:**
  - Independent audit logging requires a database role that can write security events even when support transactions abort.
  - If the audit connection holds broad query permissions, credentials leaked from the gateway could compromise customer data or expose forensic audit history.
  - Revocation consistency must be formally defined to prevent race conditions during concurrent logout and refresh.
  - Unconstrained `WITH CHECK (true)` allows fabricated audit rows that only satisfy enum CHECKs.
- **Options Considered:**
  - _Option A: Runtime Role Audit Writing & Optimistic Cache Guarantees (Rejected)._ Audit records roll back on transaction abort, and cached credentials can leak during concurrent logout.
  - _Option B: Dedicated Blind Append-Only Role (`dcmp_audit_writer`) with Constrained INSERT & DB-Linearized Check (Selected; Revised Phase 2.1.11)._
- **Decision:**
  - Adopt **Option B** with Phase 2.1.11 trust-boundary rules.
  - Provision `dcmp_audit_writer` (`LOGIN, NOBYPASSRLS`) on a dedicated pool; commit audit inserts on a connection independent of the request transaction.
  - **Phase 2.1.12:** `GRANT INSERT` only — **no SELECT privilege**. Direct SELECT → `42501 permission denied` (not “0 rows”).
  - INSERT policy: `WITH CHECK (recorded_by = CURRENT_USER AND event_source = 'GATEWAY')` plus BEFORE INSERT normalization.
  - `CURRENT_USER` proves the DB role, **not** the human actor.
  - Enum CHECKs constrain categories only; they do **not** prove event authenticity if writer credentials are compromised.
  - Cache-hit / logout: DB check COMMIT linearizes authorization; in-flight HTTP delivery after that commit is an **acknowledged residual window**.
- **Justification:**
  - Contains audit-role blast radius without false authenticity, false SELECT semantics, or zero-window claims.

---

### ADR-022: Retry-Aware DPoP Nonce Protocol & Composite Idempotency Ordering

- **Context:**
  - Token refresh rotates the server DPoP nonce.
  - If a mobile client experiences a network timeout and transparently retransmits the exact same refresh request, validating the active nonce prior to checking the retry cache rejects legitimate retries with `401 Unauthorized` (`USE_DPOP_NONCE`).
  - Pipe-delimited concatenation without length/line rules is collision-prone.
- **Options Considered:**
  - _Option A: Validate Active Nonce Before Cache Lookup (Rejected)._ Breaks mobile retry idempotency upon server nonce rotation.
  - _Option B: Evaluate Composite Retry Cache Before Nonce Check (Selected; Revised Phase 2.1.11 encoding)._
- **Decision:**
  - Adopt **Option B** with `dcmp-retry-key-v1` (Phase 2.1.12 / ADR-030): UTF-8 line-oriented fields; lowercase UUID/hex; **preserve path trailing slashes**; omit default ports; reject empty fields and refresh URIs with query strings; SHA-256 hex verified with Python/Node.
  - Lookup order: Redis (optional) → PostgreSQL `refresh_idempotency_records` → nonce/JTI/rotation path.
  - Perform idempotency lookup **before** active nonce validation.
- **Justification:**
  - Preserves mobile retry idempotency with unambiguous hashing and durable DB recovery.

---

### ADR-023: Constant-Time Cryptographic Limits & PostgreSQL LEAKPROOF Semantics

- **Context:**
  - PL/pgSQL executes via PostgreSQL SPI and backend executor; byte loops cannot guarantee instruction-level constant-time execution due to interpreter overhead and CPU cache jitter.
  - PostgreSQL `LEAKPROOF` is an optimizer directive for security-barrier views, not a timing side-channel guarantee.
- **Options Considered:**
  - _Option A: Claim Mathematical Constant-Time via LEAKPROOF PL/pgSQL (Rejected)._ Technically inaccurate and misrepresents engine guarantees.
  - _Option B: Explicit Length Validation, Double-Hashing & Defense-in-Depth Residual Risk Disclosure (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - `dcmp_security.constant_time_eq` asserts exact 32-byte digest inputs before bitwise folding.
  - Do not mark the function `LEAKPROOF` to imply timing safety.
  - Document that network and TLS encapsulation jitter (0.5ms–5.0ms) swamping nanosecond microarchitectural variances, combined with Gateway rate-limiting and 15-minute SSA expiration, provides effective practical resistance.
- **Justification:**
  - Conforms to high-assurance security engineering standards by clearly distinguishing engine capability from theoretical ideals.

---

### ADR-024: Hardened Audit-Writer Boundary, FORCE RLS & Nullable Organization Attribution

- **Context:**
  - Audit logs must be durable even when request transactions abort.
  - Attackers presenting invalid or non-existent tenant UUIDs in authorization attacks would cause audit log insertion to fail on foreign key constraint `23503`, rolling back security event logging.
- **Options Considered:**
  - _Option A: Mandatory Tenant FK on All Audit Records (Rejected)._ Allows attackers to evade audit logging by supplying invalid organization UUIDs.
  - _Option B: Nullable Tenant Attribution with FORCE RLS and Forensic Payload Recording (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Configure `organization_id UUID NULL` on `public.security_events`.
  - When an unverified or invalid tenant UUID is attacked, write `organization_id = NULL` (platform-global forensic event) and store the attempted UUID in `details JSONB -> 'attempted_org_id'`.
  - Enable `FORCE ROW LEVEL SECURITY` on `security_events` with blind append-only policies (`USING false` for `dcmp_audit_writer`).
  - Attach statement-level immutability trigger blocking `UPDATE, DELETE, TRUNCATE` (`42501`).
- **Justification:**
  - Guarantees unconditional audit capture of authorization attacks without breaking relational database integrity.

---

### ADR-025: Dual-Tier Permissive & Restrictive RLS Policy Composition

- **Context:**
  - In PostgreSQL, if row security is enabled on a table and only `RESTRICTIVE` policies are defined, the absence of an applicable `PERMISSIVE` policy causes PostgreSQL to evaluate access as `FALSE` by default, resulting in 0 rows returned for all queries.
- **Options Considered:**
  - _Option A: Sole Restrictive Policies (Rejected)._ Triggers PostgreSQL default-deny behavior for intended operations.
  - _Option B: Dual-Tier Composition with Explicit Permissive and Restrictive Policies (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Every table protected by RLS must define an explicit `AS PERMISSIVE` policy granting the allowed command set (SELECT, INSERT, UPDATE, DELETE) to the authorized role, combined with an `AS RESTRICTIVE` policy enforcing tenant boundary checks.
  - Ensures tenant-root (`organizations`), tenant-owned, platform support, and audit tables behave predictably without default-deny lockouts.
- **Justification:**
  - Correctly implements PostgreSQL 16 RLS Boolean composition ($(\bigvee \text{Permissive}) \wedge (\bigwedge \text{Restrictive})$) while preserving strict multi-tenant isolation.

---

### ADR-026: Single-Use Challenge & Transaction-Bound Support Authorization

- **Context:**
  - Unbound support HMAC signatures could theoretically be copied from custom GUCs and replayed across transactions or connections before grant expiration.
- **Options Considered:**
  - _Option A: Reliance on Transaction-Local GUCs alone (Rejected)._ An attacker or rogue connection can execute `set_config` in another transaction with copied values.
  - _Option B: Single-Use Challenge Table & Active Transaction ID Binding (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Introduce table `dcmp_security.support_session_challenges`.
  - `dcmp_security.open_support_session` atomically consumes a single-use challenge (`consumed_at = clock_timestamp(), transaction_xid = txid_current()`).
  - Canonical HMAC binds $\text{org\_id}$, $\text{grant\_id}$, $\text{admin\_id}$, $\text{challenge\_id}$, and PostgreSQL's active top-level transaction ID (`txid_current()::text`).
  - `verify_support_signature` recomputes the HMAC using active transaction context. Replaying GUCs in another transaction fails signature verification due to transaction ID mismatch and consumed challenge status.
- **Justification:**
  - Eliminates cross-transaction signature replay attacks and binds support sessions cryptographically to their active database transaction.

---

### ADR-027: Dedicated Statement TRUNCATE Trigger & In-Flight DPoP Concurrency Serialization

- **Context:**
  - In PostgreSQL, `BEFORE UPDATE OR DELETE` triggers do not intercept `TRUNCATE` operations; `TRUNCATE` requires a dedicated statement-level `BEFORE TRUNCATE` trigger.
  - Concurrent DPoP requests arriving simultaneously before cache population could race to consume JTIs or duplicate database token rotation.
- **Options Considered:**
  - _Option A: Generic DML Triggers & Optimistic Retry Lookups (Rejected)._ Leaves `TRUNCATE` unprotected and risks false replay rejections under lock contention.
  - _Option B: Dedicated BEFORE TRUNCATE Trigger & Redlock Bounded Waiting with Post-Lock Cache Recheck (Selected)._
- **Decision:**
  - Adopt **Option B**.
  - Deploy a dedicated statement-level `BEFORE TRUNCATE` trigger on `public.security_events` raising exception `42501`.
  - Enforce Redlock `redlock:refresh:<sessionId>` as an **optimization** with bounded waiting (2000ms). Concurrent workers acquiring the lock execute a **Post-Lock Double-Checked Cache Lookup**. Correctness remains the PostgreSQL conditional token UPDATE (ADR-019). Redis lock failure modes must fail closed, not invent recovery guarantees.
- **Justification:**
  - Closes the audit log truncation loophole and documents concurrency controls without treating Redlock as a sole security boundary.

---

### ADR-028: PostgreSQL-Backed Refresh Idempotency Records

- **Context:** Redis retry-cache loss after a committed token rotation previously forced hard-reuse revocation on legitimate identical retries.
- **Options Considered:**
  - _Option 1: Durable PG idempotency ciphertext (Selected)._
  - _Option 2: Explicit reauthentication only (Rejected as sole production design)._
- **Decision:** Add tenant-owned entity `refresh_idempotency_records` (entity #63, Stage 1). Store AES-256-GCM ciphertext (Vault key never in DB), fingerprint = `dcmp-retry-key-v1` SHA-256, TTL 60s, invalidate on logout. See Phase 2.1.12 §2.
- **Justification:** Keeps PostgreSQL authoritative for both serialization and legitimate retry recovery.

### ADR-029: Organization Lifecycle Column-Level Privileges & Trigger Guard

- **Context:** RLS `USING (true) WITH CHECK (true)` did not enforce lifecycle-only column updates.
- **Decision:** Column-level `GRANT UPDATE` for platform-admin lifecycle columns; separate grants for `dcmp_app` profile columns; BEFORE UPDATE trigger blocks cross-class mutations (`42501`). See Phase 2.1.12 §4.
- **Justification:** Database-enforced least privilege without relying on application validation alone.

### ADR-030: Path-Preserving Canonical Retry-Key Encoding with Verified Digests

- **Context:** Prior specs stripped trailing slashes, collapsing distinct HTTP routes; digests were not computed.
- **Decision:** Preserve path trailing slashes; publish verified SHA-256 vectors (Python + Node). See Phase 2.1.12 §7.
- **Justification:** Unambiguous, collision-resistant fingerprints aligned with HTTP semantics.

---

## 3. Implementation Readiness Sign-Off

ADR-001 through ADR-030 are reconciled. Phase 2.1.12 Corrections A–F are the authoritative security baseline for validation.

| Gate                                  | Result  |
| ------------------------------------- | ------- |
| ADR register reconciled               | Yes     |
| SQL executed against PostgreSQL 16    | **No**  |
| Security tests passed                 | **No**  |
| APPROVED FOR POSTGRESQL 16 VALIDATION | **Yes** |
| Approved for Phase 2.2 implementation | **No**  |

Authoritative correction report: [PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md](PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md).
