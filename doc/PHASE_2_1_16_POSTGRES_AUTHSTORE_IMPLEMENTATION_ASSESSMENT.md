# DCMP Phase 2.1.16 — Postgres AuthStore Implementation Assessment

**Date:** November 22, 2026  
**Environment verified:** PostgreSQL **16.10** / `dcmp_validation` / `127.0.0.1:55432` (running)  
**Code freeze until assessment complete:** Yes (this document precedes production changes)

---

## 1. Existing persistence interface

`AUTH_STORE` / `AuthStore` (`auth-store.port.ts`) methods used by `AuthService`:

| Method | Purpose |
| ------ | ------- |
| `findUserByEmail(email, organizationId?)` | Login credential lookup |
| `createSession(session, initialToken)` | Login session + first refresh token |
| `getSession(org, sessionId)` | Session state / jkt / active |
| `getTokenByHash(tokenHash)` | Resolve refresh presentation |
| `findIdempotency(org, session, fp)` | Durable recovery lookup |
| `rotateRefresh(...)` | Conditional consume + insert token + idempotency |
| `revokeSession(org, session)` | Logout / reuse path |
| `invalidateIdempotency(org, session)` | Called from revoke |

**Memory-only leaks into AuthService (must fix):**

- `seedTestUser` → `MemoryAuthStore.seedUser`
- `requireUserEmail` → `this.store.users.find(...)`

These must become port methods: `findUserById`, `upsertUser` / `seedUser` (test), so PostgreSQL can implement them.

**DI today:** `AUTH_STORE` → `MemoryAuthStore` only (`auth.module.ts`).

---

## 2. Required PostgreSQL tables and columns

| Entity | Present | Gap vs AuthStore |
| ------ | ------- | ---------------- |
| `organizations` | Yes | OK |
| `users` | Yes | **Missing `password_hash`**; no `roles`; activity via `deleted_at` |
| `user_sessions` | Yes | Maps cleanly |
| `user_session_tokens` | Yes | Maps cleanly; `token_hash` globally UNIQUE |
| `refresh_idempotency_records` | Yes | Maps cleanly; immutability trigger + `UPDATE(invalidated_at)` only |
| `security_events` | Yes | Optional audit sink (INSERT-only for audit writer) |

---

## 3. Required SQL functions

| Function | Status | Need |
| -------- | ------ | ---- |
| `invalidate_refresh_idempotency(org, session)` | Exists (INVOKER) | Reuse |
| Login email lookup under RLS | **Missing** | Without org GUC, `dcmp_app` sees 0 rows |
| Token hash lookup under RLS | **Missing** | Same: hash is unique but RLS still requires org GUC |

**Proposed narrowly scoped SECURITY DEFINER helpers** (owner `dcmp_sec_definer`, `NOBYPASSRLS`, fixed `search_path`, `EXECUTE` to `dcmp_app` only):

1. `dcmp_security.lookup_user_for_login(p_email TEXT)` → id, organization_id, password_hash, display_name, roles, deleted_at  
2. `dcmp_security.lookup_token_by_hash(p_hash CHAR(64))` → token + session binding columns  

These return **at most one row** by unique key (email active / token_hash). They do **not** grant general cross-tenant SELECT to `dcmp_app`. After lookup, the app sets `SET LOCAL app.current_organization_id` and performs all mutations as `dcmp_app` under FORCE RLS.

---

## 4. Missing schema elements (validation-only additions)

Script: `infrastructure/database-validation/sql/09_auth_gateway_persistence.sql`

1. `ALTER TABLE public.users ADD COLUMN IF NOT EXISTS password_hash TEXT;`  
2. `ALTER TABLE public.users ADD COLUMN IF NOT EXISTS roles TEXT[] NOT NULL DEFAULT ARRAY['inspector']::text[];`  
3. SECURITY DEFINER lookup functions above + grants.  
4. Optional: ensure `dcmp_app` can `SET` GUC `app.current_organization_id` (already used in prior validation).

**Not in scope:** full 63-entity schema, Prisma migrations for production, password reset tables.

---

## 5. RLS and privilege requirements

- Runtime role: **`dcmp_app`** — not SUPERUSER, not BYPASSRLS (verified Phase 2.1.13).  
- FORCE RLS on users/sessions/tokens/idempotency.  
- Restrictive policy: `organization_id = current_setting('app.current_organization_id')::uuid`.  
- Empty/missing GUC → fail-closed (0 rows).  
- Idempotency: `SELECT`/`INSERT` + `UPDATE (invalidated_at)` only.  
- Connection bootstrap may use `dcmp_val_super` then `SET SESSION AUTHORIZATION dcmp_app` for disposable trust auth — never use PG 18.

---

## 6. Transaction design

`rotateRefresh` must be a single `BEGIN … COMMIT` as `dcmp_app`:

1. `SET LOCAL app.current_organization_id = :org`  
2. Idempotency `SELECT … FOR SHARE` by fingerprint  
3. Session `SELECT … FOR SHARE` require `is_active`  
4. Conditional `UPDATE` token `consumed_at` … `RETURNING`  
5. On 0 rows: re-read idempotency (identical) else revoke + invalidate → `TOKEN_REUSE`  
6. `INSERT` new token + idempotency `ON CONFLICT DO NOTHING`  
7. `COMMIT`  

Matches Phase 2.1.12 §2.7; do not invent a second algorithm.

Pool: `pg.Pool`; every unit of work opens a client, begins a transaction, sets GUC **LOCAL**, commits/rolls back, releases client — **no GUC left on idle pooled connections**.

---

## 7. Tenant-context strategy

| Layer | Current | Required |
| ----- | ------- | -------- |
| `TenantMiddleware` | Sets `req.tenant.organizationId` from **client header** | Annotate **claim only** (`claimedOrganizationId`); never authorize |
| Auth refresh/logout | Partially denies header ≠ session org | Keep; derive org from **token/session DB lookup** |
| Protected APIs (`/me`) | Access JWT `orgId` | Document HS256 scaffold; verify sid/org from token claims + optional session check |
| PostgreSQL | GUC from app | Set only from verified DB-derived org after lookup helpers |

---

## 8. Files expected to change / create

### Create

- `doc/PHASE_2_1_16_POSTGRES_AUTHSTORE_IMPLEMENTATION_ASSESSMENT.md` (this file)  
- `doc/PHASE_2_1_16_POSTGRES_AUTHENTICATION_INTEGRATION_REPORT.md`  
- `infrastructure/database-validation/sql/09_auth_gateway_persistence.sql`  
- `apps/backend/src/modules/auth/persistence/postgres-auth.store.ts`  
- `apps/backend/src/modules/auth/persistence/pg.pool.ts`  
- `apps/backend/src/modules/auth/tenant/verified-tenant.context.ts`  
- `apps/backend/src/modules/auth/__tests__/postgres-auth.integration.spec.ts`  
- Evidence under `infrastructure/database-validation/evidence/phase-2.1.16/`

### Modify

- `auth-store.port.ts` (add `findUserById`, seed/upsert for tests)  
- `memory-auth.store.ts` (implement new port methods)  
- `auth.service.ts` (remove Memory-only coupling; use port)  
- `auth.module.ts` (env-selected AUTH_STORE)  
- `tenant.middleware.ts` (untrusted claim annotation)  
- `configuration.ts` (validation DB URL)  
- `package.json` test scripts  

---

## 9. Implementation risks

| Risk | Mitigation |
| ---- | ---------- |
| Login/token lookup blocked by RLS without org | SECURITY DEFINER single-row lookup helpers |
| GUC leak across pool | `SET LOCAL` only inside transactions; release client after |
| Weakening RLS to pass tests | Forbidden — no BYPASSRLS on app role |
| Dual rotation algorithms | Port must mirror Memory/Phase 2.1.12 semantics exactly |
| Password column in validation DB only | Document as validation-only; production Prisma later |
| HS256 access tokens | Document assessment; optional `cnf.jkt` claim addition without breaking clients if additive |

---

## 10. Go / no-go

**GO** for Stages B–H with narrowly scoped SQL `09_*` and PostgresAuthStore wired via DI when `AUTH_STORE_DRIVER=postgres` (or test suite explicitly selects it).

Memory adapter remains available; evidence must separate memory vs PostgreSQL results.
