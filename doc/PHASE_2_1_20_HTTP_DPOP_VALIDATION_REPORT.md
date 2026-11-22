# Phase 2.1.20 — HTTP / DPoP Validation Report

## Summary

NestJS HTTP endpoints were exercised against **real PostgreSQL 16.10** (`dcmp_validation` @ `127.0.0.1:55432`) and **real Redis**, using the Phase 2.1.17 ES256 DPoP-bound access-token architecture. No mocks were substituted for Redis or PostgreSQL.

## Endpoints exercised

| Method | Path                                 | Result coverage                              |
| ------ | ------------------------------------ | -------------------------------------------- |
| POST   | `/api/v1/auth/login`                 | PASSED                                       |
| POST   | `/api/v1/auth/refresh`               | PASSED (incl. concurrency / fail-closed)     |
| POST   | `/api/v1/auth/logout`                | PASSED                                       |
| GET    | `/api/v1/auth/me`                    | PASSED (valid) / denied after logout         |
| POST   | `/api/v1/auth/sessions/status`       | PASSED (session still active after bad DPoP) |
| GET    | `/api/v1/auth/.well-known/jwks.json` | PASSED                                       |
| GET    | `/api/v1/health/live`                | PASSED                                       |
| GET    | `/api/v1/health/ready`               | PASSED                                       |

## DPoP / auth cases

| Test ID          | Scenario                                    | Result |
| ---------------- | ------------------------------------------- | ------ |
| DB-SEC-018       | Valid login + JWKS + me with DPoP AT        | PASSED |
| DB-SEC-019       | Invalid DPoP signature; session not revoked | PASSED |
| DB-SEC-028       | Reused JTI rejected (Redis SET NX)          | PASSED |
| DB-SEC-021       | Logout then `/me` denied                    | PASSED |
| DB-SEC-ORG-HDR   | Spoofed `x-organization-id` → 403           | PASSED |
| DB-SEC-DPOP-HTM  | Wrong `htm`                                 | PASSED |
| DB-SEC-DPOP-KEY  | Wrong DPoP key                              | PASSED |
| DB-SEC-REDIS-203 | Redis down → 503 fail-closed                | PASSED |

## Security model

RFC 9449-aligned proof binding (method, URI, `ath`, `jkt`/`cnf`, nonce, JTI) was **not** weakened. Client organization headers remain non-authoritative.

## Limitations

- TEST-ONLY local ES256 signing keys (`AUTH_ALLOW_LOCAL_KEYS`).
- Not a full matrix of every expired/`nbf`/`ath` edge from Phase 2.1.17 unit/integration suites; those prior results remain retained.
- Production KMS and Flutter DPoP client migration remain separate gates.

## Evidence

`infrastructure/database-validation/evidence/phase-2.1.20/`
