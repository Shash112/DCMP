# Phase 2.1.20 — Refresh Concurrency Report

## Summary

Refresh-token rotation, identical-proof idempotent retry, and divergent-proof failure were validated with **independent concurrent HTTP clients** against PostgreSQL 16.10 + real Redis.

## Authority split

| Concern | Authority |
|---------|-----------|
| Refresh rotation / reuse detection / idempotent recovery | **PostgreSQL** (durable) |
| DPoP JTI / nonce admission | **Redis** (ephemeral, fail-closed) |

Redis must not become the sole source of truth for durable refresh correctness. Observed behavior matches that design.

## Executed cases

| Test ID | Scenario | Result | Detail |
|---------|----------|--------|--------|
| DB-SEC-071 | Identical concurrent refresh (same proof/fingerprint) | PASSED | `statuses=200,200` (PG idempotency recovery) |
| DB-SEC-072 | Divergent proofs same refresh token | PASSED | one 200 / one 401 |
| DB-SEC-028 | JTI replay after successful rotation | PASSED | second proof with reused JTI → 401 |
| DB-SEC-REDIS-203 | Redis unavailable during refresh | PASSED | 503 |
| DB-SEC-019 | Bad DPoP does not revoke | PASSED | session remains active |
| DB-SEC-021 | Retry after logout | PASSED | protected route denied |

## Not run

| Test ID | Reason |
|---------|--------|
| DB-SEC-REDIS-RESTART | Physical Redis restart mid-refresh requires Docker control |
| DB-SEC-REFRESH-PG-ROLLBACK | Explicit mid-transaction kill harness not built |
| DB-SEC-PROCESS-INTERRUPT | Process crash injection not built |
| DB-SEC-REDIS-TIMEOUT | No dedicated timeout injection |

## Evidence hygiene

Request IDs appear in Nest/pino logs. Access tokens, refresh tokens, private keys, and HMAC secrets are redacted in logger config and were not written to evidence JSON.

## Evidence path

`infrastructure/database-validation/evidence/phase-2.1.20/phase_2_1_20_cases.json`
