# DCMP Phase 2.1.18 — Schema Inventory Reconciliation

**Date:** November 22, 2026  
**Authority:** `PHASE_2_1_DATABASE_DESIGN_REVIEW.md` §3 (63-entity table) + ADR-003/028 + Phase 2.1.12–17 SQL  
**Target DB (this phase):** `dcmp_full_schema_validation` @ PostgreSQL 16.10 `:55432`  
**Preserved DB:** `dcmp_validation` (Stage 1 / auth validation — not overwritten)

---

## 1. Conflicts resolved

| Conflict | Resolution |
| -------- | ---------- |
| ADR-003 / 2.1.12 text calls refresh idempotency “entity #63” | Inventory table assigns **`refresh_idempotency_records` = #12**; **`generated_files` = #63**. Meaning of ADR: adding refresh raised total from 62→63. **Numbering follows §3 inventory table.** |
| Stage 1 “20 tables” vs Phase 2.1.13 SQL | 2.1.13 implemented a **security subset**, not full Stage 1. Full Stage 1 = 20 entities per design review. |
| SQL 09/10 (`password_hash`, `roles`, login DEFINER) | **Validation-only auth columns/functions**. Included in full-schema Stage 1 as documented extensions; not a 64th entity. |
| `dcmp_security.*` internal tables | Support crypto tables (Stage 7 hardening) — **not** counted in the 63 public entities. |
| Prisma schema files | **None present** in repo — Prisma compatibility **NOT RUN** / deferred. |

**Verified total public entities: 63.**

---

## 2. Existing SQL vs master inventory

| Source | Coverage |
| ------ | -------- |
| `sql/00`–`08` (dcmp_validation) | Roles, org, users, sessions, tokens, refresh_idempotency, security_events, support stubs, RLS/grants/functions — **partial Stage 1 + Stage 7 security slice** |
| `sql/09`–`10` | Auth gateway columns + login identity DEFINER helpers |
| Stages 2–6 domain tables | **Missing** from prior validation SQL |
| Full Stage 1 identity/org structure (roles, locations, …) | **Missing** from prior validation SQL |

---

## 3. Ownership summary (ADR-003)

| Class | Count | RLS |
| ----- | ----- | --- |
| Platform-Global | 9 | None |
| Tenant-Root | 1 (`organizations`) | FORCE |
| Tenant-Owned | 51 | FORCE |
| Cross-Cutting | 2 (`platform_admin_audit_logs`, `security_events`) | FORCE (nullable org) |
| **Total** | **63** | |

Platform-Global (9): platform_admins, platform_roles, platform_permissions, platform_admin_role_assignments, platform_role_permissions, permissions, license_plans, license_plan_entitlements, application_releases.

---

## 4. Authoritative inventory (implementation status pre-2.1.18)

Status codes: `ABSENT` = not in full-schema migrations yet; `PARTIAL` = subset in dcmp_validation only; `PLANNED` = this phase.

| # | Entity | Domain | Ownership | Stage | RLS | Prior status |
| - | ------ | ------ | --------- | ----- | --- | ------------ |
| 1 | organizations | Platform | Tenant-Root | 1 | Y | PARTIAL |
| 2 | organization_domains | Platform | Tenant-Owned | 1 | Y | ABSENT |
| 3 | organization_settings | Platform | Tenant-Owned | 1 | Y | ABSENT |
| 4 | platform_admins | Platform | Platform-Global | 1 | N | ABSENT |
| 5 | platform_roles | Platform | Platform-Global | 1 | N | ABSENT |
| 6 | platform_permissions | Platform | Platform-Global | 1 | N | ABSENT |
| 7 | platform_admin_role_assignments | Platform | Platform-Global | 1 | N | ABSENT |
| 8 | platform_role_permissions | Platform | Platform-Global | 1 | N | ABSENT |
| 9 | users | Identity | Tenant-Owned | 1 | Y | PARTIAL (+09/10) |
| 10 | user_sessions | Identity | Tenant-Owned | 1 | Y | PARTIAL |
| 11 | user_session_tokens | Identity | Tenant-Owned | 1 | Y | PARTIAL |
| 12 | refresh_idempotency_records | Identity | Tenant-Owned | 1 | Y | PARTIAL |
| 13 | roles | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 14 | permissions | Identity | Platform-Global | 1 | N | ABSENT |
| 15 | role_permissions | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 16 | user_roles | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 17 | locations | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 18 | departments | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 19 | teams | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 20 | user_organizational_assignments | Identity | Tenant-Owned | 1 | Y | ABSENT |
| 21 | license_plans | Platform | Platform-Global | 2 | N | ABSENT |
| 22 | license_plan_entitlements | Platform | Platform-Global | 2 | N | ABSENT |
| 23 | customer_licenses | Platform | Tenant-Owned | 2 | Y | ABSENT |
| 24 | license_events | Platform | Tenant-Owned | 2 | Y | ABSENT |
| 25 | application_releases | Platform | Platform-Global | 2 | N | ABSENT |
| 26 | assets | Identity | Tenant-Owned | 2 | Y | ABSENT |
| 27 | mobile_devices | Mobile | Tenant-Owned | 2 | Y | ABSENT |
| 28 | device_user_sessions | Mobile | Tenant-Owned | 2 | Y | ABSENT |
| 29 | checklist_categories | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 30 | checklist_templates | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 31 | checklist_versions | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 32 | checklist_sections | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 33 | checklist_questions | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 34 | question_options | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 35 | question_conditions | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 36 | checklist_version_snapshots | Templates | Tenant-Owned | 3 | Y | ABSENT |
| 37 | checklist_schedules | Scheduling | Tenant-Owned | 4 | Y | ABSENT |
| 38 | checklist_assignments | Scheduling | Tenant-Owned | 4 | Y | ABSENT |
| 39 | assignment_targets | Scheduling | Tenant-Owned | 4 | Y | ABSENT |
| 40 | inspection_instances | Inspection | Tenant-Owned | 5 | Y | ABSENT |
| 41 | inspection_responses | Inspection | Tenant-Owned | 5 | Y | ABSENT |
| 42 | inspection_evidence | Inspection | Tenant-Owned | 5 | Y | ABSENT |
| 43 | approval_records | Inspection | Tenant-Owned | 5 | Y | ABSENT |
| 44 | inspection_history | Inspection | Tenant-Owned | 5 | Y | ABSENT |
| 45 | issues | Issues | Tenant-Owned | 6 | Y | ABSENT |
| 46 | corrective_actions | Issues | Tenant-Owned | 6 | Y | ABSENT |
| 47 | corrective_action_history | Issues | Tenant-Owned | 6 | Y | ABSENT |
| 48 | sync_operations | Mobile | Tenant-Owned | 6 | Y | ABSENT |
| 49 | sync_logs | Mobile | Tenant-Owned | 6 | Y | ABSENT |
| 50 | notifications | Notifications | Tenant-Owned | 7 | Y | ABSENT |
| 51 | notification_preferences | Notifications | Tenant-Owned | 7 | Y | ABSENT |
| 52 | notification_delivery_logs | Notifications | Tenant-Owned | 7 | Y | ABSENT |
| 53 | push_device_tokens | Notifications | Tenant-Owned | 7 | Y | ABSENT |
| 54 | support_tickets | Support | Tenant-Owned | 7 | Y | ABSENT |
| 55 | support_ticket_comments | Support | Tenant-Owned | 7 | Y | ABSENT |
| 56 | support_diagnostics | Support | Tenant-Owned | 7 | Y | ABSENT |
| 57 | support_access_requests | Support | Tenant-Owned | 7 | Y | PARTIAL (stub) |
| 58 | support_access_grants | Support | Tenant-Owned | 7 | Y | PARTIAL (stub) |
| 59 | support_access_logs | Support | Tenant-Owned | 7 | Y | ABSENT |
| 60 | audit_logs | Audit | Tenant-Owned | 7 | Y | ABSENT |
| 61 | platform_admin_audit_logs | Audit | Cross-Cutting | 7 | Y | ABSENT |
| 62 | security_events | Audit | Cross-Cutting | 7 | Y | PARTIAL |
| 63 | generated_files | Reporting | Tenant-Owned | 7 | Y | ABSENT |

**Count check:** 63 rows. Stages: 1=20, 2=8, 3=8, 4=3, 5=5, 6=5, 7=14 → 20+8+8+3+5+5+14 = **63**.

---

## 5. Security functions & auth extensions to carry forward

| Object | Action in full schema |
| ------ | --------------------- |
| `invalidate_refresh_idempotency` | Stage 1 / security |
| `dcmp_security.lookup_*` (09/10) | Stage 1 auth helpers |
| `dcmp_security.verify_support_signature` / `open_support_session` | Stage 7 |
| Idempotency ciphertext immutability trigger | Stage 1 |
| Org lifecycle column grants + trigger | Stage 1 |

---

## 6. Files expected this phase

- `infrastructure/database-validation/full-schema/migrations/*.sql` (ordered stages)
- `run-full-schema-validation.ps1`
- DB-SEC suite under `full-schema/tests/`
- Evidence under `evidence/phase-2.1.18/`
- Final inventory + validation report docs

**Post-implementation note:** Full DDL applied to `dcmp_full_schema_validation` (63/63 IMPLEMENTED). See `PHASE_2_1_18_FINAL_SCHEMA_INVENTORY.md` and `PHASE_2_1_18_FULL_SCHEMA_AND_DB_SEC_VALIDATION_REPORT.md`.
