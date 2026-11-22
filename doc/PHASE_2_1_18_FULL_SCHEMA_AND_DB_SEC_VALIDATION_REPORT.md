# DCMP Phase 2.1.18 — Full Schema & DB-SEC Validation Report

**Date:** November 22, 2026  
**Target database:** `dcmp_full_schema_validation`  
**Preserved database:** `dcmp_validation` (Stage 1 auth — not overwritten)  
**Engine:** PostgreSQL **16.10** @ `127.0.0.1:55432` (local EDB/binaries cluster; PostgreSQL 18 not used; Docker not started)

---

## 1. Executive decision

# VALIDATION PARTIAL — BLOCKED

Full **63-entity / seven-stage** DDL applied and catalog-validated on a disposable database. Core tenant RLS, composite FK, role-boundary, audit-writer, and auth DEFINER helper checks **executed and PASSED (0 FAILED)** on `dcmp_full_schema_validation`.

**Not** a full Phase 2.1.18 “FULL SCHEMA VALIDATION PASSED” claim: **71** DB-SEC scenarios remain **NOT_RUN** (Redis, HTTP/DPoP gateway, SSA HMAC pack, multi-connection pool harness, and several Stage 7 crypto helpers). Phase **2.2 remains blocked**.

---

## 2. Entity inventory reconciliation

See `doc/PHASE_2_1_18_SCHEMA_INVENTORY_RECONCILIATION.md` and `doc/PHASE_2_1_18_FINAL_SCHEMA_INVENTORY.md`.

| Check                                   | Result                                             |
| --------------------------------------- | -------------------------------------------------- |
| Master inventory count                  | **63**                                             |
| Implemented public entity tables        | **63**                                             |
| Numbering conflict (#12 vs #63 refresh) | Resolved per §3 inventory table                    |
| SQL 09/10 auth extensions               | Incorporated as helpers/columns, not a 64th entity |
| `dcmp_security.*` tables                | Present; excluded from 63                          |

---

## 3. Tables and migrations

| Stage                 | Script                                       | Result                                 |
| --------------------- | -------------------------------------------- | -------------------------------------- |
| Roles/schemas         | `S00_roles_and_schemas.sql`                  | Applied                                |
| Stage 1 (20)          | `S01_stage1_foundation.sql`                  | Applied                                |
| Stage 2 (8)           | `S02_stage2_licensing_devices.sql`           | Applied                                |
| Stage 3 (8)           | `S03_stage3_checklists.sql`                  | Applied                                |
| Stage 4 (3)           | `S04_stage4_assignments.sql`                 | Applied                                |
| Stage 5 (5)           | `S05_stage5_inspections.sql`                 | Applied                                |
| Stage 6 (5)           | `S06_stage6_issues_sync.sql`                 | Applied                                |
| Stage 7 (14)          | `S07_stage7_notifications_support_audit.sql` | Applied                                |
| RLS                   | `S08_apply_rls.sql`                          | Applied (54 FORCE RLS)                 |
| Grants + auth helpers | `S09_grants_and_auth_helpers.sql`            | Applied (+ org column grant hardening) |
| Catalog gate          | `S10_catalog_validate.sql`                   | Applied / re-validated                 |

Evidence: `evidence/phase-2.1.18/migration_execution.log`, `catalog_revalidate.log`.

---

## 4. Constraints and relationships

| Metric                   | Observed                                                                      |
| ------------------------ | ----------------------------------------------------------------------------- |
| Entity tables            | 63                                                                            |
| Foreign keys             | 104                                                                           |
| Indexes                  | 133                                                                           |
| Composite tenant FKs     | Present (e.g. checklist category→template; question_conditions version-bound) |
| Deferred self-FK         | `user_session_tokens.replaced_by` `ON DELETE NO ACTION DEFERRABLE`            |
| Idempotency immutability | Trigger allows only `invalidated_at`                                          |

Cross-tenant composite FK and cross-version question_conditions **PASSED** in DB-SEC suite.

---

## 5. RLS and tenant isolation

| Requirement                                             | Status                               |
| ------------------------------------------------------- | ------------------------------------ |
| FORCE RLS on tenant-root / tenant-owned / cross-cutting | **PASSED** (54 tables)               |
| Empty GUC fail-closed                                   | **PASSED** (users + templates)       |
| Cross-tenant SELECT/UPDATE/DELETE                       | **PASSED**                           |
| Cross-tenant INSERT                                     | **PASSED** (RLS WITH CHECK)          |
| Tenant-root org isolation                               | **PASSED**                           |
| Platform-admin GUC spoof ignored                        | **PASSED**                           |
| Org lifecycle column grants                             | **PASSED** (app cannot set `status`) |
| Pooled connection isolation harness                     | **NOT_RUN**                          |
| SSA / support signature path                            | **NOT_RUN** (helpers not re-ported)  |

Tenant context remains `app.current_organization_id` via `SET LOCAL` pattern; client org headers are not authorization (unchanged from 2.1.16/17 Nest design on `dcmp_validation`).

---

## 6. Role and permission validation

| Role                  | SUPERUSER | BYPASSRLS | Notes                              |
| --------------------- | --------- | --------- | ---------------------------------- |
| `dcmp_app`            | f         | f         | Runtime; no sec_definer membership |
| `dcmp_migrator`       | f         | f         | DDL owner                          |
| `dcmp_platform_admin` | f         | f         | Org lifecycle columns only         |
| `dcmp_sec_definer`    | f         | f         | Owns DEFINER helpers               |
| `dcmp_audit_writer`   | f         | f         | INSERT-only on `security_events`   |
| `dcmp_cleanup`        | f         | f         | Present                            |

Executed: SET ROLE escalation denied under `SET SESSION AUTHORIZATION`; CREATE TABLE denied; PUBLIC EXECUTE revoked on login lookup; DEFINER `search_path` fixed; `internal_keys` denied to app.

---

## 7. DB-SEC execution matrix (`dcmp_full_schema_validation`)

| Status             | Count                                                    |
| ------------------ | -------------------------------------------------------- |
| **PASSED**         | **47**                                                   |
| **FAILED**         | **0**                                                    |
| **BLOCKED**        | **0**                                                    |
| **NOT_RUN**        | **71**                                                   |
| **NOT_APPLICABLE** | **0**                                                    |
| **Total rows**     | **118** (official 001–101 + aliases + pack-specific IDs) |

Machine-readable: `evidence/phase-2.1.18/db_sec_matrix.json`, `db_sec_matrix.csv`, `db_sec_suite.log`.

### Carry-forward vs new DB

| Source                        | Scope                                                                                                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **New this phase**            | Full schema + SQL DB-SEC on `dcmp_full_schema_validation`                                                                                                       |
| **Preserved / carry-forward** | Auth HTTP, refresh concurrency, DPoP access-token tests on `dcmp_validation` / Nest (Phases 2.1.14–17) — **not re-executed** here; marked NOT_RUN with pointers |
| **Forbidden this phase**      | Real Redis, Docker, PostgreSQL 18                                                                                                                               |

---

## 8. Failed, blocked, not-run highlights

### FAILED

None on the final suite run.

### BLOCKED

None as execution status.

### Notable NOT_RUN

- DB-SEC-009…013, 030–035, 041–044, 062, 065–066, 077, SSA-001 — support SSA pack not re-ported
- DB-SEC-018…022, 028–029, 031, 038, 045–047, 051–055, 071–074, 086–101, AUTH-REFRESH-HTTP — HTTP/DPoP/Redis/app-layer
- DB-SEC-005, POOL-001 — multi-connection harness
- DB-SEC-070, 082 — truncate trigger / `event_source` column absent from full-schema DDL
- DB-SEC-PRISMA-001 — no Prisma files

---

## 9. Prisma compatibility

**NOT RUN.** No Prisma schema present. Raw SQL migrations are the source of truth for RLS, composite FKs, DEFERRABLE FKs, and SECURITY DEFINER objects Prisma cannot express fully.

---

## 10. Authentication continuity

| Check                                | Result                                                      |
| ------------------------------------ | ----------------------------------------------------------- |
| `dcmp_validation` still present      | Yes (9 public tables; PG 16.10)                             |
| Full-schema DB separate              | Yes — `dcmp_full_schema_validation`                         |
| Login DEFINER helpers on full schema | **PASSED** (`DB-SEC-AUTH-001/002`)                          |
| Nest/HTTP auth suite this phase      | **NOT_RUN** (preserve prior evidence; do not claim re-pass) |

---

## 11. Known gaps

1. `open_support_session` / `verify_support_signature` / `constant_time_eq` not re-ported into full-schema pack.
2. `security_events` lacks `event_source` CHECK and dedicated TRUNCATE trigger from earlier Stage-1 security subset.
3. Not every tenant table has a dedicated DML isolation case (representative domains covered).
4. Real Redis and production key management still outstanding.
5. Independent security review outstanding.
6. Flutter DPoP client migration still planned, not validated.

---

## 12. Reproducible runner

```powershell
cd C:\Users\Shashanka.AzureAD\Desktop\Projects\WLS\DCMP
powershell -NoProfile -ExecutionPolicy Bypass -File .\infrastructure\database-validation\run-full-schema-validation.ps1
```

Behavior:

- Verifies PostgreSQL 16.10 and port `55432`
- Creates `dcmp_full_schema_validation` only if missing
- **Never** auto-drops the database
- Stops on first migration failure
- Re-applies S09/S10 when schema already present
- Writes evidence under `infrastructure/database-validation/evidence/phase-2.1.18/`

---

## 13. Evidence locations

```
doc/PHASE_2_1_18_SCHEMA_INVENTORY_RECONCILIATION.md
doc/PHASE_2_1_18_FINAL_SCHEMA_INVENTORY.md
doc/PHASE_2_1_18_FULL_SCHEMA_AND_DB_SEC_VALIDATION_REPORT.md

infrastructure/database-validation/full-schema/migrations/S00–S10*.sql
infrastructure/database-validation/full-schema/tests/db_sec_suite.sql
infrastructure/database-validation/run-full-schema-validation.ps1

infrastructure/database-validation/evidence/phase-2.1.18/
  pg_version.txt
  target_db.txt
  migration_execution.log
  catalog_snapshot.txt
  catalog_revalidate.log
  schema_counts.txt
  db_sec_suite.log
  db_sec_matrix.csv
  db_sec_matrix.json
  runner_console.log
```

Prior phase evidence under `evidence/phase-2.1.13` … `phase-2.1.17` preserved.

---

## 14. Acceptance criteria scorecard

| #   | Criterion                           | Verdict                                                                 |
| --- | ----------------------------------- | ----------------------------------------------------------------------- |
| 1   | All 63 entities accounted for       | **Met**                                                                 |
| 2   | Seven migration stages execute      | **Met**                                                                 |
| 3   | Expected relationships implemented  | **Met** (catalog + sample FK tests)                                     |
| 4   | Tenant-owned RLS correct            | **Met** for applied policies; SSA path incomplete                       |
| 5   | Runtime role privilege restrictions | **Met** (executed)                                                      |
| 6   | Tenant isolation across domains     | **Partial** (representative domains; not every table case)              |
| 7   | Composite tenant-aware FKs          | **Met** (executed)                                                      |
| 8   | Migration reproducible              | **Met**                                                                 |
| 9   | No critical schema inconsistency    | **Met** for 63-entity catalog                                           |
| 10  | DB-SEC reported honestly            | **Met** (47 PASSED / 71 NOT_RUN / 0 FAILED)                             |
| 11  | Auth integration continues          | **Preserved** on `dcmp_validation`; helpers smoke-tested on full schema |
| 12  | Prior evidence not lost             | **Met**                                                                 |

---

## 15. Phase 2.2 gate

Phase 2.2 remains **blocked** until:

- Outstanding DB-SEC NOT_RUN scenarios are addressed where required
- Real Redis integration validated
- Production key management integrated
- Flutter DPoP migration planned and validated
- Independent security review completed
- Project owner explicitly authorizes Phase 2.2

---

## 16. Final decision

# VALIDATION PARTIAL — BLOCKED

Schema implementation for all 63 entities on PostgreSQL 16.10 is **complete and catalog-validated**. DB-SEC SQL core for tenant/role/audit/integrity on the new disposable database is **executed with 0 failures**. Full security program coverage (Redis, SSA, HTTP/DPoP, pool harness) is **not** complete; do not treat this as greenlight for Phase 2.2.
