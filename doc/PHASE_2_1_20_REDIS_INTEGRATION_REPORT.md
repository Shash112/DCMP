# Phase 2.1.20 — Redis Integration Report

## Summary

Real Redis is wired into the NestJS authentication gateway via `RealRedisAdapter` (`ioredis`). PostgreSQL remains the durable authority for refresh-token rotation and idempotency. Redis holds short-lived DPoP JTI / nonce state with fail-closed admission when unavailable.

## Components

| Component | Path | Role |
|-----------|------|------|
| `RealRedisAdapter` | `apps/backend/src/modules/auth/redis/real-redis.adapter.ts` | SET/GET/SET NX EX, ping, reconnect, force-unavailable |
| Driver resolution | `apps/backend/src/modules/auth/redis/redis.port.ts` | `AUTH_REDIS_DRIVER`, refuse memory when required |
| Auth module wiring | `apps/backend/src/modules/auth/auth.module.ts` | `AUTH_REDIS` → Real or Memory |
| Config | `apps/backend/src/config/configuration.ts` | host/port/db/driver/required |
| Health readiness | `apps/backend/src/modules/health/health.service.ts` | PG + Redis checks |

## Environment used

- Redis: existing local instance at `127.0.0.1:6379`, logical DB **15** for tests (`REDIS_DB=15`).
- Adapter mode: `REAL` (confirmed in evidence `00_environment.json`).
- Docker: agent **did not** start Docker Desktop or create containers. Port 6379 was already accepting connections (prior `dcmp-redis`).

## Fail-closed behavior

- `AUTH_REDIS_REQUIRED=true` (or production) refuses `MemoryRedisAdapter`.
- `enforceNonceAndJti` returns **503** `DPOP_REPLAY_STORE_UNAVAILABLE` when Redis is down.
- No silent fallback to in-memory store in required mode.

## Validated

| Case | Result |
|------|--------|
| PING + atomic SET NX | PASSED |
| TTL expiry | PASSED |
| JTI replay prevention | PASSED |
| Injected Redis unavailability during refresh | PASSED (503) |
| Readiness reflects Redis | PASSED |

## Not run

- Physical Redis container kill/restart mid-request (requires Docker control).
- Dedicated command-timeout injection under artificial latency.

## Operational assumptions

See `infrastructure/database-validation/REDIS_OPERATIONAL_NOTES.md`.

## Decision input

Real Redis integration for the auth gateway is **validated** for the disposable local instance. Production Redis HA/persistence and Vault-managed credentials remain out of scope.
