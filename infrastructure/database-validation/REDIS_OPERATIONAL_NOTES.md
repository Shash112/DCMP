# Redis operational notes (Phase 2.1.20)

## Role

Redis is the **ephemeral** store for:

- DPoP JTI replay keys (`auth:dpop_jti:*`, TTL ~120s)
- DPoP nonce keys (`auth:dpop_nonce:*`, TTL ~300s)

PostgreSQL remains durable for sessions, refresh rotation, and idempotency records.

## Configuration (non-secret)

| Variable                   | Purpose                | Safe example                    |
| -------------------------- | ---------------------- | ------------------------------- |
| `AUTH_REDIS_DRIVER`        | `real` \| `memory`     | `real`                          |
| `AUTH_REDIS_REQUIRED`      | Refuse memory fallback | `true` in shared/test/prod      |
| `REDIS_HOST`               | Host                   | `127.0.0.1`                     |
| `REDIS_PORT`               | Port                   | `6379`                          |
| `REDIS_DB`                 | Logical DB index       | `0` (prod) / `15` (local tests) |
| `REDIS_PASSWORD`           | Optional ACL password  | **never commit**                |
| `REDIS_CONNECT_TIMEOUT_MS` | Connect timeout        | `3000`                          |
| `REDIS_COMMAND_TIMEOUT_MS` | Command timeout        | `2000`                          |

## Persistence / TTL assumptions

- Auth JTI/nonce keys are short-TTL; **AOF/RDB persistence is not required** for correctness of durable refresh (PG owns that).
- Losing Redis forces **fail-closed** admission of new DPoP proofs until Redis recovers (clients receive 503 / nonce challenges as designed).
- Do not point validation tests at production Redis DB 0; use an isolated `REDIS_DB`.

## Health

- `GET /api/v1/health/live` — process up only
- `GET /api/v1/health/ready` — PostgreSQL + Redis when `REAL` / required

## Failure modes

| Condition                                         | Expected app behavior                                |
| ------------------------------------------------- | ---------------------------------------------------- |
| Redis down / forced unavailable                   | 503 replay-store unavailable for new proof admission |
| Redis reconnect                                   | ioredis retryStrategy; readiness flips when ready    |
| Memory driver in production / AUTH_REDIS_REQUIRED | **Startup refusal**                                  |

## Local validation instance

Phase 2.1.20 used an already-running Redis on `127.0.0.1:6379`. Do not assume the agent started Docker.
