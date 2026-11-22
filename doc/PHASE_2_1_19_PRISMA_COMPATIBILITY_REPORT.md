# DCMP Phase 2.1.19 — Prisma Compatibility Report

**Package:** `packages/database` (`@dcmp/database`)  
**Prisma:** 6.19.3  
**ADR-004:** Multi-file schema under `packages/database/prisma/`  
**Target DB (read-only):** `dcmp_full_schema_validation`  
**Evidence:** `evidence/phase-2.1.19/prisma_*.log`, `prisma_compat_smoke.json`

---

## 1. Actions performed

| Step | Result |
| ---- | ------ |
| `prisma db pull` (introspection) | Succeeded (64 models incl. validation `_db_sec_results`, then excluded) |
| Manual fixes for composite 1:1 relations | Added DB + Prisma `@@unique([organization_id, …])` |
| Multi-file split (63 models / 7 domain files) | Succeeded |
| `prisma validate` | **PASSED** |
| `prisma generate` | **PASSED** |
| Read-only smoke (`compat_smoke.cjs`) | **PASSED** (count orgs/users; sample templates) |
| `prisma db push` | **Not used** |

---

## 2. Layout

```
packages/database/prisma/
  schema.prisma                 # generator + datasource
  models/01_platform.prisma
  models/02_identity.prisma
  models/03_licensing_devices.prisma
  models/04_checklists.prisma
  models/05_assignments_inspections.prisma
  models/06_issues_sync.prisma
  models/07_notifications_support_audit.prisma
```

---

## 3. Constructs Prisma cannot fully represent (SQL remains source of truth)

| Construct | Notes |
| --------- | ----- |
| FORCE / RLS policies | Warning on introspect; Client does not set tenant GUC |
| CHECK constraints | Documented unsupported in Client migrations |
| DEFERRABLE FK (`fk_token_replaced_by`) | Not fully supported |
| SECURITY DEFINER functions | SQL-managed (`dcmp_security.*`) |
| Triggers (audit immutability, org lifecycle, idempotency) | SQL-managed |
| Partial privileges / column grants | SQL-managed |

Application code must continue to use transaction-local `SET LOCAL app.current_organization_id` (and SSA open for platform admin) regardless of Prisma.

---

## 4. Compatibility decision

Prisma schema validation + client generation + read-only smoke against the disposable full-schema database **succeeded**.

Destructive sync was not performed. Raw SQL migrations remain authoritative for security features.
