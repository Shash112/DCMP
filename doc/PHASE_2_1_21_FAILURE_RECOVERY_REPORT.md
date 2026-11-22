# Phase 2.1.21 — Failure / Recovery Report

Harness: `npm run test:auth:failure`  
Evidence: `infrastructure/database-validation/evidence/phase-2.1.21/failure_recovery_cases.json`

| Test ID                    | Scenario                                     | Result  | Limitation                         |
| -------------------------- | -------------------------------------------- | ------- | ---------------------------------- |
| DB-SEC-REDIS-RESTART       | Injected adapter outage → 503; recover → 200 | PASSED  | Did **not** docker-kill user Redis |
| DB-SEC-REDIS-TIMEOUT       | 1ms commandTimeout side client               | PASSED  | Disposable client only             |
| DB-SEC-REFRESH-PG-ROLLBACK | Explicit SQL ROLLBACK                        | PASSED  | Not Nest mid-refresh txn abort     |
| DB-SEC-PROCESS-INTERRUPT   | Disposable Node child SIGTERM                | PASSED  | Not Nest mid-refresh kill          |
| DB-SEC-KMS-LIVE            | Real KMS                                     | NOT_RUN | No non-prod keys                   |

User PostgreSQL and Redis services were **not** terminated.
