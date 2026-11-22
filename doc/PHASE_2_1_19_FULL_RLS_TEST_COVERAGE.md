# DCMP Phase 2.1.19 — Full RLS Test Coverage (54 FORCE-RLS tables)

**Database:** `dcmp_full_schema_validation`  
**Harness:** `infrastructure/database-validation/tests/phase-2.1.19/test_b_full_rls.py`  
**Evidence:** `evidence/phase-2.1.19/B_full_rls_results.json`

---

## 1. Catalog verification

| Metric                             | Result     |
| ---------------------------------- | ---------- |
| FORCE RLS tables                   | **54**     |
| Catalog check `DB-SEC-RLS54-COUNT` | **PASSED** |

Every FORCE-RLS table was listed from `pg_class` (not inferred from docs).

---

## 2. Per-table operations

For each of the 54 tables the harness executed (where applicable):

| Op        | Meaning                                                              |
| --------- | -------------------------------------------------------------------- |
| FORCE     | RLS enabled + FORCE confirmed                                        |
| EMPTY     | Empty tenant GUC returns 0 rows (or permission denied = fail-closed) |
| SELECT_X  | Tenant A cannot see Tenant B                                         |
| SELECT_OK | Tenant A sees own seed row when present                              |
| UPDATE_X  | Cross-tenant UPDATE affects 0 rows / denied                          |
| DELETE_X  | Cross-tenant DELETE affects 0 rows / denied                          |
| INSERT_X  | Cross-tenant INSERT rejected                                         |
| GUC_SPOOF | `app.is_platform_admin=true` does not leak Tenant B                  |

---

## 3. Execution summary

| Status         | Count   |
| -------------- | ------- |
| PASSED         | **410** |
| NOT_APPLICABLE | **23**  |
| FAILED         | **0**   |

NOT_APPLICABLE cases are primarily:

- No org-A seed row yet for some deep child tables (assignments/inspections/notifications/etc.)
- `platform_admin_audit_logs` / tables where `dcmp_app` intentionally lacks SELECT privilege (fail-closed recorded under EMPTY/SELECT_X)

No table was marked PASSED without execution. Representative deep-domain tables without seed rows were not counted as PASSED for SELECT_OK.

---

## 4. Tenant boundary notes

| Table class                 | Boundary                                                          |
| --------------------------- | ----------------------------------------------------------------- |
| `organizations`             | Tenant-root via `id`                                              |
| Most tenant-owned           | `organization_id` RESTRICTIVE policies                            |
| `security_events`           | Nullable `organization_id`; app SELECT restricted to matching org |
| `platform_admin_audit_logs` | Platform-admin policy only; app has no DML/SELECT grant           |

---

## 5. Seed

`tests/phase-2.1.19/seed_tenant_pairs.sql` seeds org A/B pairs for foundation domains. Additional tables without seed remain NOT_APPLICABLE for SELECT_OK only; isolation ops still executed.
