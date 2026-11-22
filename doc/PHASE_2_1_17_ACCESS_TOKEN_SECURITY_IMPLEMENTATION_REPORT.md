# DCMP Phase 2.1.17 — Access Token Security Implementation Report

**Date:** November 22, 2026  
**Branch:** `main` (no commit / no push)  
**Final decision:** **IMPLEMENTATION VALIDATED**  
**Phase 2.2:** **Blocked**

Architecture decision: [PHASE_2_1_17_ACCESS_TOKEN_ARCHITECTURE_DECISION.md](PHASE_2_1_17_ACCESS_TOKEN_ARCHITECTURE_DECISION.md)  
Client migration: [PHASE_2_1_17_CLIENT_MIGRATION_NOTES.md](PHASE_2_1_17_CLIENT_MIGRATION_NOTES.md)

| Gate                                | Result                                        |
| ----------------------------------- | --------------------------------------------- |
| ES256 asymmetric access tokens      | **Yes**                                       |
| `iss` / `aud` enforced              | **Yes**                                       |
| `cnf.jkt` bound to login DPoP key   | **Yes**                                       |
| Protected APIs require DPoP + `ath` | **Yes** (`/auth/me`, `/auth/sessions/revoke`) |
| Replay protection fail-closed       | **Yes** (memory Redis)                        |
| PostgreSQL session introspection    | **Yes**                                       |
| Logout blocks protected access      | **Yes**                                       |
| Login multi-org ambiguity resolved  | **Yes**                                       |
| Signing-key rotation                | **Yes** (local provider)                      |
| No production keys hardcoded        | **Yes**                                       |
| PostgreSQL HTTP tests               | **16/16 access + 14/14 regression**           |
| Memory regression                   | **12/12**                                     |
| Real Redis / KMS                    | **NOT RUN**                                   |

---

## 1. Executive summary

Phase 2.1.17 retires the HS256 Bearer scaffold. Access tokens are ES256-signed JWTs with `iss`, `aud`, `cnf.jkt`, and short TTL, presented as `Authorization: DPoP` with RFC 9449 proofs (`ath` required). Protected routes verify JWT + DPoP + PostgreSQL session state. Login no longer silently picks among duplicate emails across organizations. Production KMS and real Redis remain NOT RUN.

---

## 2. Architecture decision

**Selected:** ES256 + DPoP sender constraint (`cnf.jkt`) with `token_type=DPoP`. HS256 Bearer rejected on protected routes. See decision document.

---

## 3. Token format

| Field                                     | Value                                    |
| ----------------------------------------- | ---------------------------------------- |
| Header                                    | `alg=ES256`, `kid`, `typ=at+jwt`         |
| `iss`                                     | `https://auth.dcmp.local` (env override) |
| `aud`                                     | `dcmp-api`                               |
| `sub`                                     | user id                                  |
| `sid` / `orgId` / `roles` / `type=access` | yes                                      |
| `iat` / `nbf` / `exp` / `jti`             | yes (TTL ≤ 15m)                          |
| `cnf.jkt`                                 | login/refresh session DPoP thumbprint    |
| Response `tokenType`                      | `DPoP`                                   |

---

## 4. Signing and verification

- `AccessTokenSigningKeyProvider` + `LocalAccessTokenKeyProvider` (test ES256 keys).
- `UnconfiguredProductionAccessTokenKeyProvider` stub — KMS **NOT RUN**.
- Verify via public JWK by `kid`; unknown/retired kid rejected.
- Refresh AES-GCM keys remain separate (`LocalTestKeyProvider`).

---

## 5. JWKS

`GET /api/v1/auth/.well-known/jwks.json` — public keys only (`kty`, `crv`, `x`, `y`, `kid`, `use`, `alg`).

---

## 6. DPoP binding

Login stores `dpop_jkt` on the session and embeds the same value in `cnf.jkt`. Protected requests: proof JWK thumbprint must equal `cnf.jkt` and session `dpop_jkt`; proof must include matching `ath`.

---

## 7. Protected API verification

`DpopBoundAuthGuard` → `AuthService.authorizeProtectedResource`:

1. Reject non-`DPoP` Authorization scheme
2. ES256 JWT verify (iss/aud/type/cnf)
3. `validateDpopProof` with `accessToken` + `expectedJkt`
4. JTI replay (fail-closed)
5. PostgreSQL session active / subject / org / jkt

---

## 8. Session introspection

Authoritative store: PostgreSQL via AuthStore. JWT alone is insufficient. No Redis session authority.

---

## 9. Login identity resolution

Email uniqueness in the validation model is **organization-scoped** (not globally unique).

SQL `10_login_identity_resolution.sql`:

- `lookup_user_for_login(email, org)` — org filter when supplied; without org returns ambiguity signal when `match_count > 1`
- App: ambiguous → `LOGIN_ORGANIZATION_REQUIRED` (400); none/wrong password → generic `UNAUTHENTICATED`

---

## 10. Key management

| Provider                  | Status                       |
| ------------------------- | ---------------------------- |
| Local ES256 test keys     | Implemented                  |
| AWS KMS / Secrets Manager | Interface stub — **NOT RUN** |

---

## 11. API compatibility and migration

Breaking: `tokenType` → `DPoP`; protected routes require DPoP Authorization + proof. Flutter not modified this phase — see client migration notes.

---

## 12. Test results

| Suite                          | Command                      | Result    |
| ------------------------------ | ---------------------------- | --------- |
| Memory (2.1.15)                | `npm run test:auth:memory`   | **12/12** |
| Postgres AuthStore (2.1.16)    | `npm run test:auth:postgres` | **14/14** |
| Access-token security (2.1.17) | `npm run test:auth:access`   | **16/16** |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.17/`

---

## 13. Failed, blocked, not-run

| Item                                      | Status                                                 |
| ----------------------------------------- | ------------------------------------------------------ |
| Real Redis                                | **NOT RUN**                                            |
| Production KMS signing                    | **NOT RUN**                                            |
| Dedicated expired-AT clock skew HTTP case | **NOT RUN** (jose rejects expired; covered by library) |
| Dedicated reused protected-route JTI case | **NOT RUN** (mechanism shared with refresh)            |
| Deleted/inactive user login HTTP          | **NOT RUN**                                            |
| Flutter client update                     | **Not in scope**                                       |
| Full 63-entity schema                     | **Not applied**                                        |
| Independent security review               | **Outstanding**                                        |

---

## 14. Remaining security gaps

1. Local test signing keys ≠ production readiness.
2. Real Redis replay store unproven.
3. Rate limiting on login not expanded this phase.
4. Platform-admin boundary unchanged.
5. Only `/me` and session revoke use the guard today — other modules must adopt `DpopBoundAuthGuard` when built.

---

## 15. Files changed (focus)

**Created:** access-token key providers, `DpopBoundAuthGuard`, SQL `10_login_identity_resolution.sql`, access-token security tests, architecture/migration/report docs.

**Modified:** `auth.service.ts`, `auth.controller.ts`, `auth.module.ts`, AuthStore login lookup, `shared-types` / `api-contracts`, postgres HTTP tests for DPoP Authorization.

---

## 16. Evidence paths

`infrastructure/database-validation/evidence/phase-2.1.17/`

- `10_login_identity.apply.log`
- `memory-adapter-http-tests.log`
- `postgres-adapter-http-tests.log`
- `access-token-security-http-tests.log`

---

## 17. Final recommendation

**IMPLEMENTATION VALIDATED** for Phase **2.1.17**.

Do **not** start Phase 2.2 until full schema/DB-SEC validation, real Redis where required, production key integration, independent security review, and explicit owner authorization.
