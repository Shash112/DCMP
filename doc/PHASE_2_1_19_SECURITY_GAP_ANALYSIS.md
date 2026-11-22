# DCMP Phase 2.1.19 — Security Gap Analysis

**Date:** November 22, 2026  
**Baseline:** Phase 2.1.18 (47 PASSED / 71 NOT_RUN / 0 FAILED on `dcmp_full_schema_validation`)  
**Engine:** PostgreSQL 16.10 @ `127.0.0.1:55432`  
**Git:** `main` @ `dbc80b34…` (dirty working tree; no commit)

---

## 1. Baseline verification

| Item                          | Observed                                |
| ----------------------------- | --------------------------------------- |
| `dcmp_full_schema_validation` | Present; 63 entity tables; 54 FORCE RLS |
| `dcmp_validation`             | Preserved (9 public tables)             |
| PostgreSQL                    | 16.10 only (PG18 not used)              |
| Docker / Redis                | Not started / not installed             |

---

## 2. Gaps closed this phase (SQL)

| Gap (2.1.18)                                    | Resolution                                                           | Migration |
| ----------------------------------------------- | -------------------------------------------------------------------- | --------- |
| `security_events.event_source` missing          | Column + CHECK + insert trigger                                      | S11       |
| TRUNCATE protection missing                     | `BEFORE TRUNCATE` + UPDATE/DELETE triggers                           | S11       |
| Audit-writer restrictions incomplete            | Column grants + WITH CHECK `event_source='GATEWAY'`                  | S11       |
| `constant_time_eq` / SSA functions absent       | Ported + adapted to full-schema columns                              | S11       |
| `internal_keys` / challenges incomplete for SSA | Additive columns (`key_secret`, status, validity, org, challenge_id) | S11       |
| FORCE RLS blocked DEFINER grant reads           | Policies for `dcmp_sec_definer` on support request/grant             | S12       |
| JWT base64url padding                           | `b64url_to_bytea` helper                                             | S13       |
| Prisma composite 1:1 uniqueness                 | Composite UNIQUE constraints                                         | S14       |

---

## 3. Gaps explicitly remaining (out of this phase or app-layer)

| Gap                           | Status                                          |
| ----------------------------- | ----------------------------------------------- |
| Real Redis                    | NOT_RUN (phase restriction)                     |
| Production KMS / Vault        | NOT_RUN                                         |
| Nest HTTP gateway SSA minting | NOT_RUN (SQL path validated)                    |
| Flutter DPoP client migration | NOT_RUN                                         |
| Independent security review   | NOT_RUN                                         |
| Prisma Client RLS enforcement | Architectural limitation — app must `SET LOCAL` |

---

## 4. Environment-executable tests

Executable now: SQL catalog, RLS54, pool isolation, SSA SQL, audit triggers, Prisma validate/generate/smoke.  
Not executable without new infra: Redis, production keys, Flutter, independent review.
