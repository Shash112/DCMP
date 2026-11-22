# DCMP Phase 2.1.15 — Authentication Gateway & DPoP Report

**Date:** November 22, 2026  
**Branch:** `main` (no commit/push)  
**Final decision:** **IMPLEMENTATION PARTIAL — BLOCKED**

| Gate | Result |
| ---- | ------ |
| NestJS auth endpoints exist | **Yes** |
| RFC 9449 DPoP validation | **Yes** (ES256) |
| Replay protection (JTI) fail-closed | **Yes** (memory Redis; real Redis NOT RUN) |
| URI binding + proxy spoofing tests | **Yes** |
| Refresh idempotency integrated | **Yes** (MemoryAuthStore mirrors PG semantics) |
| AES-GCM + `dcmp-refresh-aad-v1` in Auth service | **Yes** |
| HTTP integration tests | **12/12 PASSED** |
| Real Redis | **NOT RUN** |
| Postgres refresh adapter against `dcmp_validation` | **NOT RUN** |
| Full 63-entity schema | **Not applied** |
| Phase 2.2 | **Blocked** |

---

## 1. Executive summary

Phase 2.1.15 implements a real NestJS authentication boundary with RFC 9449 DPoP proof validation, refresh rotation, AES-256-GCM recoverable responses, and fail-closed replay-store behavior. HTTP integration tests passed (12/12) against an in-memory authoritative store and memory Redis adapter. Real Redis and live PostgreSQL adapter wiring remain **NOT RUN**. Phase 2.2 is not authorized.

Assessment: [PHASE_2_1_15_IMPLEMENTATION_ASSESSMENT.md](PHASE_2_1_15_IMPLEMENTATION_ASSESSMENT.md)

---

## 2. Existing implementation assessment

Pre-phase: `AuthModule` was an empty placeholder; no JWT/DPoP libraries; contracts/schemas existed; PG validation harnesses from 2.1.13–14 were not an Auth gateway. Tenant middleware still trusts client org headers for request annotation — refresh/logout **deny** client org spoofing via session binding.

---

## 3. Architecture and request flow

```
Client
  │  DPoP header + body
  ▼
AuthController (/api/v1/auth/*)
  ▼
AuthService
  1. Validate request DTO
  2. validateDpopProof (typ, alg, jwk, sig, htm, htu, iat, jkt)
  3. Resolve session from refresh token hash (server-side org)
  4. Reject client org header ≠ session.organizationId
  5. Idempotency lookup by dcmp-retry-key-v1 fingerprint
     → if hit: decrypt AES-GCM response (invalid proof never reaches here)
  6. Else: nonce match + JTI SET NX (fail-closed if Redis down)
  7. Conditional rotate / hard reuse revoke
  8. Encrypt response, persist idempotency
  9. Best-effort Redis retry cache
 10. Return tokens + DPoP-Nonce
```

Reconciled with Phase 2.1.12: **crypto-valid DPoP first**; **idempotency before JTI consumption** for identical retries; invalid proofs never recover credentials.

---

## 4. DPoP implementation details

| Rule | Behavior |
| ---- | -------- |
| `typ` | Must be `dpop+jwt` |
| `alg` | `ES256` only; reject `none` / symmetric |
| `jwk` | Public EC P-256; reject private fields (`d`, …) |
| Signature | Verified via `jose` |
| `htm` / `htu` | Must match request method and canonical URI |
| `iat` | `maxTokenAge` 120s, clock skew 5s |
| `jti` | Required; atomic NX store TTL 120s |
| `ath` | Required only when access token presented |
| `nonce` | Required on refresh after server issued `DPoP-Nonce` |
| Invalid proof | 401 `DPOP_PROOF_FAILED` — **session not revoked** |

Files: `apps/backend/src/modules/auth/dpop/*`

---

## 5. URI canonicalization

- Lowercase scheme/host; strip default ports 80/443.  
- **Preserve path trailing slash** (Phase 2.1.12 Correction F).  
- Reject query/fragment in `htu`.  
- When `DCMP_PUBLIC_ORIGIN` is set, scheme/host come from that origin; `X-Forwarded-*` are **ignored** for binding (spoofing test covered).

---

## 6. Replay protection design

| Store | Key | TTL | Failure policy |
| ----- | --- | --- | -------------- |
| JTI | `auth:dpop_jti:<jti>` | 120s | If Redis unavailable → **503** `DPOP_REPLAY_STORE_UNAVAILABLE` for **new** proofs (fail-closed). Identical-proof **recovery** still allowed after crypto OK via idempotency (before JTI gate). |
| Nonce | `auth:dpop_nonce:<sessionId>` | 300s | Mismatch → 401 `USE_DPOP_NONCE` + new nonce header |

Mode in this phase: **MEMORY** / **SIMULATED_FAILURE**. Real Redis client **NOT RUN**.

---

## 7. Authentication and refresh transaction sequence

Implemented in `AuthService.refresh` / `MemoryAuthStore.rotateRefresh`:

- Conditional consume of presented token hash.  
- Insert replacement token + idempotency row.  
- Concurrent identical fingerprint → `RECOVERED`.  
- Divergent reuse → revoke session + `TOKEN_REUSE_DETECTED`.

PostgreSQL adapter against `dcmp_validation` is designed via `AUTH_STORE` port but **not wired in this phase’s HTTP suite** (NOT RUN).

---

## 8. AES-GCM integration and key management

| Item | Value |
| ---- | ----- |
| Algorithm | AES-256-GCM |
| IV | 96-bit CSPRNG |
| Tag | 128-bit |
| AAD | `dcmp-refresh-aad-v1` + org/session/fp/hashes/jkt/kid/expiry |
| Key provider | `RefreshCipherKeyProvider` + `LocalTestKeyProvider` |
| Production | Local provider **refuses** `NODE_ENV=production` without explicit `AUTH_ALLOW_LOCAL_KEYS` (not for real prod) |

---

## 9. Redis behavior

- `AuthRedisPort` + `MemoryRedisAdapter` with `setAvailable(false)` failure injection.  
- Retry cache non-authoritative.  
- Real Redis: **NOT RUN** (Docker not started; no install).

---

## 10. API endpoints and contracts

| Method | Path | Notes |
| ------ | ---- | ----- |
| POST | `/api/v1/auth/login` | DPoP required; returns user + tokens + `DPoP-Nonce` |
| POST | `/api/v1/auth/refresh` | DPoP + refreshToken |
| POST | `/api/v1/auth/logout` | DPoP + refreshToken; revokes session |
| GET | `/api/v1/auth/me` | Bearer access token |
| POST | `/api/v1/auth/sessions/revoke` | Explicit revoke |
| POST | `/api/v1/auth/sessions/status` | Active check |

Extended: `HTTP_HEADERS.DPOP`, `DPOP_NONCE`; error codes for DPoP/reuse/replay.

---

## 11. Security controls

- No client org override on refresh.  
- No private JWK acceptance.  
- Pino redacts `dpop`, `authorization`, tokens.  
- Audit events without token material.  
- Production blocks default JWT secrets and local cipher keys.

---

## 12. Test cases and execution evidence

Command: `pnpm --filter @dcmp/backend run test:auth`

| Test | Result |
| ---- | ------ |
| URI trailing slash / forwarded header spoof | PASSED |
| AES-GCM tamper / AAD / expiry | PASSED |
| Login + refresh rotation | PASSED |
| Invalid signature (no revoke) | PASSED |
| Wrong method / URI | PASSED |
| Same-proof retry recovery | PASSED |
| Divergent reuse revocation | PASSED |
| Client org spoof denied | PASSED |
| Redis unavailable fail-closed (SIMULATED) | PASSED |
| Logout blocks recovery | PASSED |
| Reused JTI on non-recovery | PASSED |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.15/`

---

## 13. Failed, blocked and not-run

| Item | Status |
| ---- | ------ |
| Failed HTTP tests | **0** |
| Real Redis integration | **NOT RUN** |
| Postgres `dcmp_validation` refresh adapter HTTP | **NOT RUN** |
| Concurrent dual-connection Nest HTTP (2.1.14 PG harness) | Covered at store semantics; Nest dual-conn stress **NOT RUN** |
| Support SSA gateway E2E | **NOT RUN** |
| Independent security review | Outstanding |
| Full DB-SEC-001…101 via gateway | Partial; many remain NOT RUN |

---

## 14. Known limitations

1. Authoritative store for HTTP suite is **in-memory**, not live PG RLS.  
2. Access tokens use HS256 scaffold secrets (not DPoP-bound access tokens yet).  
3. Login password hashing is scrypt local — not full IdP.  
4. No AWS Secrets Manager provider yet (interface ready).  
5. Tenant middleware still annotates from client headers (must not be used for authz).

---

## 15. Files changed / created

### Created (high level)

- `doc/PHASE_2_1_15_IMPLEMENTATION_ASSESSMENT.md`  
- `doc/PHASE_2_1_15_AUTHENTICATION_GATEWAY_AND_DPOP_REPORT.md`  
- `apps/backend/src/modules/auth/**` (controller, service, dpop, crypto, redis, persistence, audit, dto, errors, tests)  
- `infrastructure/database-validation/evidence/phase-2.1.15/**`

### Modified

- `apps/backend/package.json` (`jose`, `pg`, `tsx`, `test:auth`)  
- `apps/backend/src/config/configuration.ts`  
- `apps/backend/src/app.module.ts` (redaction)  
- `packages/api-contracts` headers, routes, error codes  
- Lockfile via pnpm

---

## 16. Local setup and test commands

```powershell
# Ensure packages built if consuming dist contracts
pnpm --filter @dcmp/api-contracts exec tsc -p tsconfig.json

# Auth HTTP + DPoP suite
pnpm --filter @dcmp/backend run test:auth

# Optional: typecheck
pnpm --filter @dcmp/backend exec tsc --noEmit
```

Do **not** start Docker for this phase. Optional PG 16 validation cluster remains on `127.0.0.1:55432` for future adapter tests.

---

## 17. Remaining DB-SEC coverage

Gateway now addresses previously NOT RUN DPoP/HTTP themes (018/019-class). Full matrix still ~half NOT RUN pending schema, real Redis, and broader SQL scenarios. Phase 2.1.14 matrix remains the baseline inventory.

---

## 18. Final recommendation

**IMPLEMENTATION PARTIAL — BLOCKED**

Recommend next:

1. Wire `PostgresAuthStore` to disposable PG 16 and re-run HTTP suite.  
2. Add real Redis under explicit approval (keep fail-closed JTI policy).  
3. Replace HS256 access scaffold with production key management / DPoP-bound access where required.  
4. Independent security review.  
5. **Do not start Phase 2.2** until owner authorization after remaining validation.
