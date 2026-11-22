# DCMP Phase 2.1.15 — Implementation Assessment

**Date:** November 22, 2026  
**Branch:** `main` (local uncommitted Phase 2.1.x work preserved)  
**Scope:** Authentication gateway + RFC 9449 DPoP before any Phase 2.2 work

---

## 1. Existing implementation inventory

| Area | Status | Location |
| ---- | ------ | -------- |
| NestJS backend scaffold | Present | `apps/backend/` |
| `AuthModule` | **Empty placeholder** | `apps/backend/src/modules/auth/auth.module.ts` |
| Auth HTTP controllers/services/guards | **Absent** | — |
| JWT libraries (`jose`, `passport`, `@nestjs/jwt`) | **Absent** from `package.json` | Config secrets only in `configuration.ts` |
| Prisma / DB client in backend | **Absent** | `DATABASE_URL` config only |
| Redis client | **Absent** | Host/port config only |
| API routes (login/refresh/logout/me) | Contracts only | `packages/api-contracts/src/routes.ts` |
| Auth Zod schemas | Login/refresh shapes only | `packages/validation-schemas/src/auth.schema.ts` |
| Shared auth types | Present | `packages/shared-types/src/auth.ts` |
| Tenant middleware | Present; **trusts client `X-Organization-Id`** | `tenant.middleware.ts` |
| Pino redaction | Partial (`authorization`, `refreshToken`) | `app.module.ts` |
| PG validation SQL (sessions, tokens, idempotency, SSA) | Present (disposable) | `infrastructure/database-validation/` |
| Phase 2.1.14 harnesses (concurrency, AES, RedisSim, SSA) | Present | `tests/phase-2.1.14/` |
| Jest/Vitest | **Absent** in monorepo | — |
| Docker Compose for PG16 | Prepared, not required | `infrastructure/docker/` |

---

## 2. Missing implementation components

1. DPoP proof validator (RFC 9449 §4.3).  
2. Canonical `htu` builder (trailing-slash preserve per Phase 2.1.12 Correction F).  
3. Replay store (JTI) with fail-closed policy when cache unavailable.  
4. Server nonce issuance/verification for refresh.  
5. Auth controller endpoints: login, refresh, logout, me, revoke.  
6. Refresh orchestration with PG-authoritative rotation + idempotency.  
7. AES-256-GCM response cipher with `dcmp-refresh-aad-v1` and injectable key provider.  
8. Redis port + memory/failure adapters (real Redis NOT RUN without approval).  
9. Auth audit event emitter (no token material).  
10. HTTP-level integration tests.

---

## 3. Reusable code

- API route constants and envelopes.  
- Login/Refresh Zod schemas (extend for DPoP header handling).  
- Exception filter / response interceptor patterns.  
- Phase 2.1.12/14 algorithms: conditional token UPDATE, idempotency ON CONFLICT, AAD format, retry-key vectors.  
- Disposable PG 16.10 `dcmp_validation` for optional live DB tests.  
- Phase 2.1.14 AES vectors and concurrency expectations.

---

## 4. Architectural conflicts to reconcile

| Conflict | Resolution for 2.1.15 |
| -------- | --------------------- |
| Design review “retry cache before JTI” vs naive “JTI first” | Validate DPoP crypto first; **idempotency/retry lookup before consuming JTI/nonce** for identical proofs; never recover on invalid proof |
| Redlock as concurrency guarantee (older text) | Superseded by Phase 2.1.12 PG barrier; Redlock optional optimization only |
| Symmetric JWT refresh secrets in config | Access tokens may use HS256 for Phase 2.1.15 scaffold; **DPoP proofs require asymmetric ES256 only** |
| Tenant middleware trusts client org header | Authz for refresh/logout **must** use session/token DB binding, not client headers |
| Full Prisma Stage 1 not applied | Use repository port: in-memory for HTTP suite + optional Postgres adapter against validation DB |

---

## 5. Security risks (pre-implementation)

| Risk | Severity |
| ---- | -------- |
| No DPoP → bearer refresh alone | Critical (current state) |
| Client org header as authorization | High |
| Dev JWT secrets in config defaults | Medium (forbid in production mode) |
| Redis outage silently skipping JTI | High if fail-open — **must fail-closed** for new proofs; recovery still via PG idempotency after crypto OK |
| Logging tokens | Controlled via redaction expansion |

---

## 6. Proposed implementation sequence

1. Assessment (this document).  
2. Shared header/error code extensions.  
3. DPoP URI + validator + JWK thumbprint.  
4. Key provider + AES-GCM cipher.  
5. Redis port (memory + fail-inject) + JTI/nonce services.  
6. Auth persistence port (memory primary; optional PG).  
7. AuthService refresh/login/logout orchestration.  
8. AuthController + module wiring.  
9. Node native test runner HTTP suite + evidence.  
10. Final Phase 2.1.15 report.

---

## 7. Exact files expected to change / create

### Create

- `apps/backend/src/modules/auth/**` (controller, service, dpop, crypto, redis, persistence, audit, dto, errors)  
- `apps/backend/src/modules/auth/__tests__/**`  
- `doc/PHASE_2_1_15_AUTHENTICATION_GATEWAY_AND_DPOP_REPORT.md`  
- `infrastructure/database-validation/evidence/phase-2.1.15/**`

### Modify

- `apps/backend/src/modules/auth/auth.module.ts`  
- `apps/backend/src/config/configuration.ts`  
- `apps/backend/package.json` (add `jose`, `pg` types as needed; test script)  
- `packages/api-contracts/src/headers.ts`, `status-codes.ts`  
- `packages/validation-schemas/src/auth.schema.ts` (if needed)  
- `apps/backend/src/app.module.ts` (redact DPoP / expand secrets)

### Must not change

- Full 63-entity migration sources as Phase 2.2  
- Flutter / unrelated frontend  
- Prior evidence under `phase-2.1.13/` / `phase-2.1.14/`

---

## 8. Dependency decisions

| Package | Purpose | Note |
| ------- | ------- | ---- |
| `jose` | JWT/JWS/DPoP/JWK thumbprint | Required for RFC 9449 |
| `pg` | Optional Postgres adapter | Validation DB only |
| Test runner | Node.js built-in `node:test` | Avoid adding Jest/Vitest unless necessary |

Redis client library deferred — memory adapter + failure injection until real Redis approved.

---

## 9. Go / no-go

**GO for Stage B–F** on NestJS AuthModule implementation with in-memory + optional PG adapters.  
**NOT RUN:** real Redis integration, full schema, Phase 2.2, independent security review.  
**Docker:** not started.
