# DCMP Phase 2.1.18 — Final Schema Inventory

**Date:** November 22, 2026  
**Database:** `dcmp_full_schema_validation` @ PostgreSQL 16.10 (`127.0.0.1:55432`)  
**Preserved:** `dcmp_validation` (Stage 1 / auth — untouched by full-schema apply)  
**Authority:** `PHASE_2_1_DATABASE_DESIGN_REVIEW.md` §3 + ADR-003/028 + inventory reconciliation

---

## 1. Totals (executed catalog)

| Metric                                         | Value                                                    |
| ---------------------------------------------- | -------------------------------------------------------- |
| Public entity tables                           | **63**                                                   |
| FORCE RLS tables                               | **54**                                                   |
| Foreign keys                                   | **104**                                                  |
| Indexes (public)                               | **133**                                                  |
| Platform-global (no RLS)                       | **9**                                                    |
| Tenant-root + tenant-owned + cross-cutting RLS | **54**                                                   |
| Migration stages applied                       | **S00–S10** (7 domain stages + roles/RLS/grants/catalog) |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.18/schema_counts.txt`, `catalog_snapshot.txt`.

---

## 2. Entity inventory (post-implementation)

| #   | Entity                          | Domain        | Ownership       | Stage | RLS | Status                                        |
| --- | ------------------------------- | ------------- | --------------- | ----- | --- | --------------------------------------------- |
| 1   | organizations                   | Platform      | Tenant-Root     | 1     | Y   | IMPLEMENTED                                   |
| 2   | organization_domains            | Platform      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 3   | organization_settings           | Platform      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 4   | platform_admins                 | Platform      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 5   | platform_roles                  | Platform      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 6   | platform_permissions            | Platform      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 7   | platform_admin_role_assignments | Platform      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 8   | platform_role_permissions       | Platform      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 9   | users                           | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED (+ auth columns)                  |
| 10  | user_sessions                   | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 11  | user_session_tokens             | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 12  | refresh_idempotency_records     | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 13  | roles                           | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 14  | permissions                     | Identity      | Platform-Global | 1     | N   | IMPLEMENTED                                   |
| 15  | role_permissions                | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 16  | user_roles                      | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 17  | locations                       | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 18  | departments                     | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 19  | teams                           | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 20  | user_organizational_assignments | Identity      | Tenant-Owned    | 1     | Y   | IMPLEMENTED                                   |
| 21  | license_plans                   | Platform      | Platform-Global | 2     | N   | IMPLEMENTED                                   |
| 22  | license_plan_entitlements       | Platform      | Platform-Global | 2     | N   | IMPLEMENTED                                   |
| 23  | customer_licenses               | Platform      | Tenant-Owned    | 2     | Y   | IMPLEMENTED                                   |
| 24  | license_events                  | Platform      | Tenant-Owned    | 2     | Y   | IMPLEMENTED                                   |
| 25  | application_releases            | Platform      | Platform-Global | 2     | N   | IMPLEMENTED                                   |
| 26  | assets                          | Identity      | Tenant-Owned    | 2     | Y   | IMPLEMENTED                                   |
| 27  | mobile_devices                  | Mobile        | Tenant-Owned    | 2     | Y   | IMPLEMENTED                                   |
| 28  | device_user_sessions            | Mobile        | Tenant-Owned    | 2     | Y   | IMPLEMENTED                                   |
| 29  | checklist_categories            | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 30  | checklist_templates             | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 31  | checklist_versions              | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 32  | checklist_sections              | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 33  | checklist_questions             | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 34  | question_options                | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 35  | question_conditions             | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 36  | checklist_version_snapshots     | Templates     | Tenant-Owned    | 3     | Y   | IMPLEMENTED                                   |
| 37  | checklist_schedules             | Scheduling    | Tenant-Owned    | 4     | Y   | IMPLEMENTED                                   |
| 38  | checklist_assignments           | Scheduling    | Tenant-Owned    | 4     | Y   | IMPLEMENTED                                   |
| 39  | assignment_targets              | Scheduling    | Tenant-Owned    | 4     | Y   | IMPLEMENTED                                   |
| 40  | inspection_instances            | Inspection    | Tenant-Owned    | 5     | Y   | IMPLEMENTED                                   |
| 41  | inspection_responses            | Inspection    | Tenant-Owned    | 5     | Y   | IMPLEMENTED                                   |
| 42  | inspection_evidence             | Inspection    | Tenant-Owned    | 5     | Y   | IMPLEMENTED                                   |
| 43  | approval_records                | Inspection    | Tenant-Owned    | 5     | Y   | IMPLEMENTED                                   |
| 44  | inspection_history              | Inspection    | Tenant-Owned    | 5     | Y   | IMPLEMENTED                                   |
| 45  | issues                          | Issues        | Tenant-Owned    | 6     | Y   | IMPLEMENTED                                   |
| 46  | corrective_actions              | Issues        | Tenant-Owned    | 6     | Y   | IMPLEMENTED                                   |
| 47  | corrective_action_history       | Issues        | Tenant-Owned    | 6     | Y   | IMPLEMENTED                                   |
| 48  | sync_operations                 | Mobile        | Tenant-Owned    | 6     | Y   | IMPLEMENTED                                   |
| 49  | sync_logs                       | Mobile        | Tenant-Owned    | 6     | Y   | IMPLEMENTED                                   |
| 50  | notifications                   | Notifications | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 51  | notification_preferences        | Notifications | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 52  | notification_delivery_logs      | Notifications | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 53  | push_device_tokens              | Notifications | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 54  | support_tickets                 | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 55  | support_ticket_comments         | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 56  | support_diagnostics             | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 57  | support_access_requests         | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED (DDL; SSA helpers not re-ported)  |
| 58  | support_access_grants           | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED (DDL; SSA helpers not re-ported)  |
| 59  | support_access_logs             | Support       | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 60  | audit_logs                      | Audit         | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |
| 61  | platform_admin_audit_logs       | Audit         | Cross-Cutting   | 7     | Y   | IMPLEMENTED                                   |
| 62  | security_events                 | Audit         | Cross-Cutting   | 7     | Y   | IMPLEMENTED (severity CHECK; no event_source) |
| 63  | generated_files                 | Reporting     | Tenant-Owned    | 7     | Y   | IMPLEMENTED                                   |

**Count:** 63 / 63.

---

## 3. Non-entity security objects

| Object                                      | Notes                                            |
| ------------------------------------------- | ------------------------------------------------ |
| `dcmp_security.internal_keys`               | Present; FORCE RLS; app denied                   |
| `dcmp_security.consumed_support_assertions` | Present; SSA open/verify **not** re-ported       |
| `dcmp_security.support_session_challenges`  | Present; SSA open/verify **not** re-ported       |
| `dcmp_security.lookup_*`                    | Login/token DEFINER helpers from Phase 2.1.16/17 |
| `invalidate_refresh_idempotency`            | Present; ciphertext immutability trigger present |

---

## 4. Numbering conflict (resolved)

ADR text that called refresh idempotency “entity #63” is **not** followed for numbering. Inventory table §3 is authoritative: **#12 = refresh_idempotency_records**, **#63 = generated_files**.

---

## 5. Prisma

No Prisma schema files found in the repository. Compatibility **NOT RUN**.
