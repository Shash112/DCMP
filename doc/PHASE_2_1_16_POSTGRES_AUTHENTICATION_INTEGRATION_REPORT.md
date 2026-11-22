# DCMP Phase 2.1.16 — PostgreSQL Authentication Integration Report

**Date:** November 22, 2026  
**Branch:** `main` (no commit / no push)  
**Final decision:** **IMPLEMENTATION VALIDATED**  
**Phase 2.2:** **Blocked** (not authorized)

| Gate | Result |
| ---- | ------ |
| PostgreSQL AuthStore in Nest DI | **Yes** (`AUTH_STORE_DRIVER=postgres`) |
| Auth HTTP tests against PostgreSQL | **14/14 PASSED** |
| Memory adapter regression | **12/12 PASSED** (reported separately) |
| Durable refresh + idempotency in PG | **Yes** |
| Independent-connection concurrency | **PASSED** (dual HTTP + dual pool GUC) |
| Tenant from server-side session/token | **Yes** |
| Client org headers cannot authorize | **Yes** (403 / claim-only middleware) |
| RLS via `dcmp_app` (NOBYPASSRLS) | **Yes** |
| Pool tenant-context isolation | **PASSED** |
| Logout / revoke block recovery | **PASSED** |
| DPoP behavior intact | **Yes** |
| Real Redis | **NOT RUN** |
| Full 63-entity schema | **Not applied** |
| Independent security review | **Outstanding** |

Assessment: [PHASE_2_1_16_POSTGRES_AUTHSTORE_IMPLEMENTATION_ASSESSMENT.md](PHASE_2_1_16_POSTGRES_AUTHSTORE_IMPLEMENTATION_ASSESSMENT.md)  
Access tokens: [PHASE_2_1_16_ACCESS_TOKEN_SECURITY_ASSESSMENT.md](PHASE_2_1_16_ACCESS_TOKEN_SECURITY_ASSESSMENT.md)

---

## 1. Executive summary

Phase 2.1.16 replaces the in-memory authoritative AuthStore for the NestJS authentication gateway with a PostgreSQL-backed implementation against disposable EDB **PostgreSQL 16.10** (`dcmp_validation` @ `127.0.0.1:55432`). Refresh rotation and AES-GCM idempotency recovery are durable under FORCE RLS as role `dcmp_app`. Tenant middleware no longer establishes authorization from client organization headers. Concurrent identical refresh succeeds across independent HTTP clients. Real Redis remains NOT RUN (memory adapter, fail-closed). Phase 2.2 is not authorized.

---

## 2. Environment verification

| Check | Value |
| ----- | ----- |
| Version | PostgreSQL **16.10** |
| Host/port | `127.0.0.1:55432` |
| Database | `dcmp_validation` |
| Bootstrap role | `dcmp_val_super` (trust, disposable) |
| Runtime role | `dcmp_app` — `rolsuper=f`, `rolbypassrls=f` |
| Start script | `infrastructure/database-validation/start-pg16-validation.ps1` |
| SQL addition | `sql/09_auth_gateway_persistence.sql` (applied) |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.16/env_verify.txt`

---

## 3. AuthStore implementation

| Component | Path |
| --------- | ---- |
| Port | `apps/backend/src/modules/auth/persistence/auth-store.port.ts` |
| Postgres store | `…/persistence/postgres-auth.store.ts` |
| Pool | `…/persistence/pg.pool.ts` (`withAppClient`, `withTenantTx` + `SET LOCAL`) |
| DI switch | `auth.module.ts` — `AUTH_STORE_DRIVER=postgres` |
| Memory store | retained for Phase 2.1.15 suite |

Operations covered: user lookup/upsert, session create/get/revoke, token-by-hash (DEFINER), idempotency find, transactional `rotateRefresh`, logout invalidation.

---

## 4. Database tables and SQL functions used

**Tables:** `organizations`, `users` (+ `password_hash`, `roles`), `user_sessions`, `user_session_tokens`, `refresh_idempotency_records`

**Functions:**

- `dcmp_security.lookup_user_for_login(email)`
- `dcmp_security.lookup_token_by_hash(hash)`
- `dcmp_security.lookup_user_by_id(org, user)`
- `public.invalidate_refresh_idempotency(org, session)`

**Grants (validation-only):** `USAGE` on `dcmp_security` to `dcmp_app`; `SELECT` + permissive RLS policies for `dcmp_sec_definer` on `users` / `user_session_tokens` so NOBYPASSRLS DEFINER lookups work before org GUC is known. `dcmp_app` does **not** receive those SELECT grants for cross-tenant reads.

---

## 5. RLS enforcement

- Mutations and tenant reads run as `dcmp_app` after `SET SESSION AUTHORIZATION`.
- Tenant GUC: `SET LOCAL app.current_organization_id` inside `BEGIN…COMMIT` only.
- Empty GUC → 0 rows (verified).
- Cross-tenant `getSession(ORG_B, sessionOfA)` → `null` (verified).

---

## 6. Tenant-context design

| Layer | Behavior |
| ----- | -------- |
| `TenantMiddleware` | Annotates `req.tenantClaim` only; does **not** set `req.tenant` for authorization |
| Login | Org from DB user row; body org mismatch → 403 |
| Refresh / logout | Org from token → session; forged `X-Organization-Id` → 403 |
| Session revoke | Requires Bearer access token with matching `orgId` + `sid` |
| Platform admin | Separate boundary (unchanged; not opened here) |

---

## 7. Transaction and idempotency behavior

`rotateRefresh` single transaction:

1. Idempotency `SELECT … FOR SHARE`
2. Session active check
3. Conditional token consume
4. Insert new token + idempotency `ON CONFLICT DO NOTHING`
5. Concurrent loser → `RECOVERED` / reuse → revoke + invalidate

AuthService: crypto-valid DPoP first; durable idempotency before JTI consumption; on JTI race, brief poll for peer-committed idempotency (concurrent identical proofs).

---

## 8. Concurrency test results

| Test | Result |
| ---- | ------ |
| Dual HTTP identical refresh | **PASSED** (same rotated token) |
| Dual pool connections, different org GUCs | **PASSED** |
| Prior Phase 2.1.14 PG harness concurrency | Preserved (not re-run as authority for HTTP) |

---

## 9. HTTP integration results

### Memory adapter (Phase 2.1.15 regression)

```
npm run test:auth:memory
→ 12/12 pass
```

Evidence: `evidence/phase-2.1.16/memory-adapter-http-tests.log`

### PostgreSQL adapter (this phase)

```
npm run test:auth:postgres
→ 14/14 pass
```

Evidence: `evidence/phase-2.1.16/postgres-adapter-http-tests.log`

Coverage includes: login/session durability, refresh + same-proof recovery, divergent reuse, concurrent refresh, logout/revoke blocking recovery, tenant spoofing, cross-tenant session denial, missing GUC, pool isolation, Redis fail-closed, invalid DPoP non-revocation.

---

## 10. Access-token security assessment

HS256 Bearer scaffold retained (no silent contract break). Missing `iss`/`aud`/`cnf.jkt`; production must not use `dev_` secrets. DPoP-bound access tokens documented as follow-on. See dedicated assessment doc.

**Residual:** bearer theft without sender constraint — **High**, explained, not remediated in 2.1.16.

---

## 11. Redis status

| Item | Status |
| ---- | ------ |
| Memory Redis adapter | Used in all HTTP tests |
| Fail-closed new proof when unavailable | **PASSED** (503 `DPOP_REPLAY_STORE_UNAVAILABLE`) on PG path |
| Real Redis server | **NOT RUN** (Docker/install forbidden) |

---

## 12. Failed, blocked, and not-run tests

| Item | Status |
| ---- | ------ |
| Memory HTTP suite | PASSED 12/12 |
| Postgres HTTP suite | PASSED 14/14 |
| Real Redis integration | **NOT RUN** |
| Injected PG connection failure mid-refresh | **NOT RUN** |
| Expired idempotency row recovery denial | **NOT RUN** (policy exists; no dedicated HTTP case) |
| Explicit ROLLBACK fault injection | **NOT RUN** (covered indirectly by exception rollback in pool) |
| Full 63-entity schema validation | **NOT RUN** |
| Independent security review | **Outstanding** |

---

## 13. Known security limitations

1. Access tokens remain HS256 Bearer without `cnf.jkt`.
2. Login email DEFINER returns first matching active user if emails collide across tenants — callers should pass organization when known.
3. Seed/`upsertUser` uses bootstrap superuser connection (validation only).
4. Real Redis not proven.
5. Audit sink still largely in-process abstraction (not full `security_events` HTTP proof).

---

## 14. Files changed / created (this phase focus)

**Created**

- `apps/backend/src/modules/auth/persistence/postgres-auth.store.ts`
- `apps/backend/src/modules/auth/persistence/pg.pool.ts`
- `apps/backend/src/modules/auth/__tests__/postgres-auth.integration.spec.ts`
- `apps/backend/src/modules/auth/__tests__/set-postgres-env.ts`
- `infrastructure/database-validation/sql/09_auth_gateway_persistence.sql`
- `doc/PHASE_2_1_16_POSTGRES_AUTHSTORE_IMPLEMENTATION_ASSESSMENT.md`
- `doc/PHASE_2_1_16_ACCESS_TOKEN_SECURITY_ASSESSMENT.md`
- `doc/PHASE_2_1_16_POSTGRES_AUTHENTICATION_INTEGRATION_REPORT.md`
- `infrastructure/database-validation/evidence/phase-2.1.16/*`

**Modified**

- `auth.module.ts`, `auth.service.ts`, `auth.controller.ts` (revoke hardening)
- `auth-store.port.ts`, `memory-auth.store.ts`
- `common/middleware/tenant.middleware.ts`
- `apps/backend/package.json` (`test:auth:memory` / `test:auth:postgres`)
- Prior 2.1.15 auth tree retained

---

## 15. Exact test commands

```powershell
cd infrastructure\database-validation
.\start-pg16-validation.ps1
# apply 09 if needed:
& "$env:PGROOT\bin\psql.exe" -h 127.0.0.1 -p 55432 -U dcmp_val_super -d dcmp_validation -f sql\09_auth_gateway_persistence.sql

cd ..\..\apps\backend
npm run test:auth:memory
npm run test:auth:postgres
```

---

## 16. Evidence paths

`infrastructure/database-validation/evidence/phase-2.1.16/`

- `env_verify.txt`
- `09_auth_gateway_persistence.apply.log`
- `memory-adapter-http-tests.log`
- `postgres-adapter-http-tests.log`

---

## 17. Final recommendation

**IMPLEMENTATION VALIDATED** for Phase **2.1.16** (PostgreSQL AuthStore + tenant hardening + HTTP/concurrency evidence on PG 16.10).

**Do not start Phase 2.2** until: remaining DB-SEC / full schema validation, real Redis where required, access-token sender-constraint decision, independent security review, and explicit owner authorization.
