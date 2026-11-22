# DCMP Phase 2.1.13 — PostgreSQL 16 Disposable Validation Report

**Date:** November 22, 2026  
**Branch:** `main`  
**Specification baseline:** Phase 2.1.12 (+ Corrections A–D applied in this phase)  
**Final decision:** **POSTGRESQL 16 VALIDATION PARTIAL — BLOCKED**

| Gate | Result |
| ---- | ------ |
| Disposable PostgreSQL **16.10** started | **Yes** (EDB Windows binaries; Docker unavailable) |
| Ordered SQL scripts executed | **Yes** (00–08) |
| Catalog validation (`08_validate_catalog.sql`) | **PASSED** |
| DB-SEC executable subset | **21 PASSED / 0 FAILED / 1 BLOCKED / 4 NOT_RUN** (of implemented IDs) |
| Full DB-SEC-001…100 coverage | **No** — many IDs remain NOT_RUN / not implemented |
| Multi-connection concurrent refresh | **BLOCKED** |
| Phase 2.2 implementation authorized | **No** |

---

## 1. Environment

| Item | Value |
| ---- | ----- |
| PostgreSQL server | **PostgreSQL 16.10**, compiled by Visual C++ build 1944, 64-bit |
| Delivery method | EDB Windows x64 binaries zip (`postgresql-16.10-1-windows-x64-binaries.zip`) |
| Bind | `127.0.0.1:55432` only |
| Database | `dcmp_validation` |
| Bootstrap user | `dcmp_val_super` (local trust; disposable) |
| Docker Desktop | **Unavailable** on Windows host (`docker.exe` not installed; WSL `docker-desktop` distro present but CLI unsupported) |
| Docker Compose file prepared | `infrastructure/docker/docker-compose.pg16-validation.yml` (`postgres:16.10-alpine`) — **not executed** |
| Existing PG 18 install | Present under `C:\Program Files\PostgreSQL\18` — **not used** (wrong major) |
| Data dir | `infrastructure/database-validation/data/pgdata` (gitignored) |
| Binaries dir | `infrastructure/database-validation/.tools/pgsql16/` (gitignored) |

---

## 2. Pre-validation specification corrections

### A. Refresh idempotency least privilege — **CORRECTED**

Supersedes `GRANT SELECT, INSERT, UPDATE` on all columns:

- `dcmp_app`: `SELECT`, `INSERT`, `UPDATE (invalidated_at)` only  
- Immutability trigger blocks fingerprint/ciphertext/IV/tag/token/DPoP/expiry mutation  
- `invalidate_refresh_idempotency` is **SECURITY INVOKER** (FORCE RLS + column grant)  
- `dcmp_cleanup`: `SELECT`, `DELETE` with restrictive policy (expired OR invalidated)  
- Negative test **DB-SEC-101 PASSED** (ciphertext UPDATE denied)

### B. AES-256-GCM AAD — **DOCUMENTED**

Canonical AAD `dcmp-refresh-aad-v1` binds org, session, fingerprint, presented token hash, issued token id, DPoP jkt, key id, expiry. 96-bit CSPRNG IV; 128-bit tag; Vault key outside DB. Documented in Phase 2.1.12 §2.5 (updated). **Encryption/decryption not executed in SQL** (application-layer); SQL stores opaque BYTEA only.

### C. Entity / Stage 1 inventory — **CORRECTED**

- Diagram heading → **63-Entity**  
- Stage 1 explicit list: **20 tables total** (6 platform-global + 1 tenant-root + 13 tenant-owned)  
- Stage 1 **RLS-enabled: 14** (1 + 13)

### D. Preflight — unresolved before run: none blocking.  
Runtime finding: migrator SECURITY DEFINER invalidation ineffective under FORCE RLS without owner policy → fixed to INVOKER before final suite.

---

## 3. SQL scripts executed (order)

| # | Script | Result |
| - | ------ | ------ |
| 00 | `00_create_roles_and_schemas.sql` | OK |
| 01 | `01_create_foundation_tables.sql` | OK |
| 02 | `02_create_identity_and_session_tables.sql` | OK |
| 03 | `03_create_refresh_idempotency.sql` | OK |
| 04 | `04_create_security_support_tables.sql` | OK |
| 05 | `05_apply_rls_policies.sql` | OK |
| 06 | `06_create_security_functions.sql` | OK |
| 07 | `07_apply_grants_and_triggers.sql` | OK |
| 08 | `08_validate_catalog.sql` | OK — `NOTICE: Catalog validation OK` |

Evidence log: `infrastructure/database-validation/evidence/sql-apply.log`

**Scope note:** Scripts implement a **security-validation subset** of Stage 1 (orgs, users, sessions, tokens, refresh idempotency, support stubs, security_events, `dcmp_security.*`). Full 63-entity DDL was **not** applied.

---

## 4. Role / privilege / RLS catalog (executed)

Verified by `08_validate_catalog.sql`:

- Runtime roles are not `SUPERUSER` / `BYPASSRLS`  
- No runtime membership in `dcmp_sec_definer`  
- `verify_support_signature` owned by `dcmp_sec_definer`  
- FORCE RLS on required public tables  
- `dcmp_audit_writer` has **no SELECT** on `security_events`  
- `dcmp_app` has **no UPDATE** on `response_ciphertext`

---

## 5. DB-SEC results (implemented IDs)

Source: `infrastructure/database-validation/evidence/db-sec-results.out`

### PASSED (21)

| ID | Area |
| -- | ---- |
| DB-SEC-001 | Tenant isolation SELECT |
| DB-SEC-003 | Cross-tenant INSERT denied by RLS |
| DB-SEC-004 | Empty tenant context → 0 rows |
| DB-SEC-026 | `SET ROLE dcmp_sec_definer` denied |
| DB-SEC-036 | Audit insert durability path |
| DB-SEC-048 | Idempotency row recoverable after rotation |
| DB-SEC-049 / 068 | Audit writer SELECT → permission denied |
| DB-SEC-050 / 070 | TRUNCATE denied by trigger |
| DB-SEC-067 | Audit INSERT success |
| DB-SEC-074 / 089 | Canonical hash vectors (Python+Node) |
| DB-SEC-082 | Bad `event_source` rejected |
| DB-SEC-094 | Logout/invalidate clears recovery |
| DB-SEC-096 | Platform admin lifecycle UPDATE |
| DB-SEC-097 / 098 | Platform admin blocked on identity/profile columns |
| DB-SEC-099 | App blocked on lifecycle columns |
| DB-SEC-100 | App profile UPDATE allowed |
| DB-SEC-101 | Ciphertext UPDATE denied |

### BLOCKED (1)

| ID | Reason |
| -- | ------ |
| DB-SEC-071 | Requires multi-connection concurrent refresh harness (not built) |

### NOT_RUN (4 in suite + majority of 001–100)

| ID | Reason |
| -- | ------ |
| DB-SEC-018 / 019 | Gateway / DPoP HTTP integration |
| DB-SEC-054 | Redis not in SQL harness |
| DB-SEC-072 | Multi-connection divergent-proof harness |
| DB-SEC-005…017, 020–025, 027–035, … | Not implemented in this harness |

**Counts for implemented suite rows:** PASSED=21, FAILED=0, BLOCKED=1, NOT_RUN=4.

**Full catalog DB-SEC-001…100:** most remain **NOT_RUN** (not implemented).

---

## 6. Canonical retry-key vectors

Independent recomputation:

| Engine | Vector 1 | Vector 3 (trailing `/`) | Match expected |
| ------ | -------- | ----------------------- | -------------- |
| Python 3.13 `hashlib` | `4a3903dd…5e72` | `9f2f6f15…d7ca` | **Yes** |
| Node.js `crypto` | same | same | **Yes** |
| Distinct | | | **Yes** |

Evidence: `evidence/hash-vectors-python.json`, `evidence/hash-vectors-node.json`

---

## 7. Reproduce

```powershell
# From repo root
powershell -ExecutionPolicy Bypass -File infrastructure/database-validation/start-pg16-validation.ps1
# Apply + test (after .env.validation exists):
$pg = (Resolve-Path infrastructure/database-validation/.tools/pgsql16/pgsql).Path
$env:Path = "$pg\bin;$env:Path"
# or use apply-sql.ps1 / run-tests.ps1 once start hang is fixed

# Docker alternative (when Docker Desktop is installed):
docker compose -f infrastructure/docker/docker-compose.pg16-validation.yml up -d
docker compose -f infrastructure/docker/docker-compose.pg16-validation.yml down -v
```

## 8. Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File infrastructure/database-validation/stop-pg16-validation.ps1
# Optional wipe data:
powershell -ExecutionPolicy Bypass -File infrastructure/database-validation/stop-pg16-validation.ps1 -Wipe
```

Binaries under `.tools/` remain unless deleted manually (gitignored).  
**This report’s run:** server left stoppable via the stop script; do not treat as a long-lived service.

---

## 9. Remaining blockers

1. **Multi-connection concurrent refresh tests** (DB-SEC-071/072) not automated.  
2. **Redis outage scenarios** not executed (no Redis in harness).  
3. **DPoP HTTP / Gateway** scenarios NOT_RUN.  
4. **Full 63-entity schema** not applied — Stage 1 security subset only.  
5. **SSA open_support_session end-to-end JWT** path not covered by a PASSED test in this run.  
6. **AES-GCM encrypt/decrypt + AAD** not executed (app-layer; SQL opaque storage only).  
7. Docker path unverified on this machine.

---

## 10. Files created / modified

### Created
- `doc/PHASE_2_1_13_POSTGRESQL_16_VALIDATION_REPORT.md` (this file)
- `infrastructure/docker/docker-compose.pg16-validation.yml`
- `infrastructure/database-validation/**` (SQL 00–08, tests, start/stop/apply/run scripts)
- Evidence under `infrastructure/database-validation/evidence/` (gitignored logs/json)

### Modified
- `doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md` — 63-Entity diagram; Stage 1 = 20/14 RLS
- `doc/PHASE_2_1_12_FINAL_ARCHITECTURE_CORRECTIONS.md` — Correction A privileges; Correction B AAD
- `.gitignore` — validation tools/data/evidence patterns

### Not modified
- Application source, Prisma schemas, production migrations — **none**

---

## 11. Final decision

### **POSTGRESQL 16 VALIDATION PARTIAL — BLOCKED**

**Rationale:** PostgreSQL **16.10** disposable execution succeeded for roles, FORCE RLS, tenant isolation, org column grants, audit INSERT-only, refresh idempotency least privilege, and catalog checks. However, the acceptance suite is incomplete (most DB-SEC IDs NOT_RUN), concurrent refresh remains BLOCKED, Redis/DPoP paths were not executed, and the full 63-entity schema was not applied.

**Do not start Phase 2.2.** Proceed to complete the blocked/not-run harness work and independent security review before any implementation authorization.
