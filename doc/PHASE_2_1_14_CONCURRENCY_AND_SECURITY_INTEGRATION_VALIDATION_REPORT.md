# DCMP Phase 2.1.14 — Concurrency, Refresh Recovery & Security Integration Validation

**Date:** November 22, 2026  
**Branch:** `main` (local; no commit/push performed)  
**Specification baseline:** Phase 2.1.12–2.1.13  
**Final decision:** **VALIDATION PARTIAL — BLOCKED**

| Gate                                                   | Result                                |
| ------------------------------------------------------ | ------------------------------------- |
| PostgreSQL 16.10 `dcmp_validation` @ `127.0.0.1:55432` | **Verified**                          |
| Docker                                                 | **Not used** (unavailable)            |
| Multi-connection refresh (A / DB-SEC-071/072)          | **10/10 PASSED**                      |
| Redis failure/recovery (B)                             | **8/8 PASSED (SIMULATED Redis only)** |
| DPoP/gateway (C)                                       | **2 PASSED / 10 NOT RUN**             |
| Support authorization SQL (D)                          | **14 PASSED / 2 NOT RUN**             |
| AES-256-GCM / AAD (E)                                  | **15/15 PASSED** (validation harness) |
| DB-SEC-001…101 matrix (F)                              | **54 PASSED / 47 NOT RUN / 0 FAILED** |
| Full 63-entity schema applied                          | **No**                                |
| Phase 2.2 authorized                                   | **No**                                |

---

## 1. Executive summary

Phase 2.1.14 executed outstanding PostgreSQL concurrency and security-integration validation on the existing disposable EDB PostgreSQL 16.10 cluster without Docker. Multi-connection refresh concurrency (including DB-SEC-071/072) and AES-GCM AAD binding were **executed and passed**. Redis scenarios were executed only against an in-process **RedisSim** (no real Redis). DPoP HTTP gateway and trusted-gateway support authentication remain **NOT RUN**. Full Stage 1–7 / 63-entity schema validation remains outstanding. Phase 2.2 stays blocked.

---

## 2. Environment and PostgreSQL version verification

| Item                   | Value                                                                  |
| ---------------------- | ---------------------------------------------------------------------- |
| Server                 | **PostgreSQL 16.10**, Visual C++ build 1944, 64-bit                    |
| Bind                   | `127.0.0.1:55432`                                                      |
| Database               | `dcmp_validation`                                                      |
| Bootstrap user         | `dcmp_val_super`                                                       |
| Public tables (subset) | 9 (security-validation Stage 1 subset; not full 63)                    |
| Binaries               | `infrastructure/database-validation/.tools/pgsql16/`                   |
| Data dir               | `infrastructure/database-validation/data/pgdata` (retained; not reset) |
| PG 18 install          | Present on host — **not used**                                         |

Evidence: `infrastructure/database-validation/evidence/phase-2.1.14/00_environment.json`

---

## 3. Docker availability note

Docker Desktop / `docker.exe` is **not available** on this Windows host. Validation continued exclusively on the existing EDB PostgreSQL 16.10 disposable cluster. The compose file from Phase 2.1.13 was **not** started.

---

## 4. Exact test harnesses and commands used

### Harness location

`infrastructure/database-validation/tests/phase-2.1.14/`

| Module                  | Purpose                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `refresh_protocol.py`   | PG-authoritative refresh rotation + idempotency (Phase 2.1.12 §2.7) |
| `test_a_concurrency.py` | Multi-connection scenarios 1–10 / DB-SEC-071/072                    |
| `test_b_redis.py`       | RedisSim failure/recovery                                           |
| `test_c_dpop.py`        | DPoP/jkt subset + NOT RUN matrix                                    |
| `test_d_support.py`     | SSA `open_support_session` / `verify_support_signature`             |
| `test_e_aes_gcm.py`     | AES-256-GCM + `dcmp-refresh-aad-v1`                                 |
| `test_f_coverage.py`    | DB-SEC-001…101 coverage matrix                                      |
| `run_all.py`            | Orchestrator                                                        |

### Local validation venv (not a product dependency)

```powershell
infrastructure\database-validation\.venv\Scripts\python.exe -m pip install -r infrastructure\database-validation\tests\phase-2.1.14\requirements.txt
cd infrastructure\database-validation\tests\phase-2.1.14
$env:PYTHONUNBUFFERED='1'
..\..\..\database-validation\.venv\Scripts\python.exe -u run_all.py
```

(Actual run used absolute paths to the same interpreter.)

### Concurrency method

Two genuinely independent `psycopg` connections (separate TCP sessions), synchronized with `threading.Barrier` — **not** sequential statements on one connection.

---

## 5. Multi-connection refresh test results

Evidence: `A_concurrency_results.json`

| ID              | Scenario                             | Result                                                            |
| --------------- | ------------------------------------ | ----------------------------------------------------------------- |
| A1 / DB-SEC-071 | Simultaneous identical proof         | **PASSED** — both 200; `max_sequence=2`; 1 active idempotency row |
| A2 / DB-SEC-072 | Simultaneous divergent proofs        | **PASSED** — 200+401; session revoked                             |
| A3              | Overlap while first tx executing     | **PASSED**                                                        |
| A4              | Retry immediately after commit       | **PASSED** — ROTATED then RECOVERED                               |
| A5              | Retry after Redis cache cleared      | **PASSED** (SIMULATED Redis) — `pg-idempotency`                   |
| A6              | Retry after PG idempotency committed | **PASSED** — same `issued_token_id`                               |
| A7              | Two requests same token rotation     | **PASSED** — 2 token rows, 1 unconsumed                           |
| A8              | Logout after refresh blocks recovery | **PASSED**                                                        |
| A9              | Revocation before recovery           | **PASSED**                                                        |
| A10             | Expired idempotency records          | **PASSED** — hard reuse 401                                       |

**Invariant check:** No case recorded a second rotation for an accepted identical proof (`invariant_violated=false` for all).

---

## 6. Redis failure and recovery results

Evidence: `B_redis_sim_results.json`

**Mode: SIMULATED only.** `redis-cli` / Redis server were not available. Do not treat these as real Redis integration tests.

| ID              | Scenario                             | Result                    |
| --------------- | ------------------------------------ | ------------------------- |
| B1              | Redis unavailable before PG tx       | **PASSED**                |
| B2              | Redis unavailable during processing  | **PASSED**                |
| B3 / DB-SEC-054 | Redis unavailable after PG commit    | **PASSED** — retry via PG |
| B4              | Cache write failure after commit     | **PASSED**                |
| B5              | Cache cleared before retry           | **PASSED**                |
| B6              | Redis recovery after outage          | **PASSED**                |
| B7              | Retry original token after DB commit | **PASSED**                |
| B8              | Retry after logout/revocation        | **PASSED** — 401          |

PostgreSQL idempotency remained the durable source of truth in the harness.

---

## 7. DPoP integration results

Evidence: `C_dpop_results.json`

| ID                     | Result      | Notes                                        |
| ---------------------- | ----------- | -------------------------------------------- |
| C-JKT / DB-SEC-095     | **PASSED**  | Wrong `dpop_jkt` on recovery → 401           |
| C-SAME                 | **PASSED**  | Same-proof PG recovery                       |
| C-VALID … C-REDIS (10) | **NOT RUN** | No HTTP DPoP verifier / Auth gateway in repo |

### Documented ordering (ADR / Phase 2.1.12)

1. Signature and claim validation — **not implemented**
2. Idempotency lookup — harness
3. Nonce/replay validation — **not implemented**
4. PG token/session validation — harness
5. Token rotation — harness
6. Durable idempotency persistence — harness

**Contradiction:** Implemented flow for this phase begins at step 2. Steps 1 and 3 cannot be validated until Auth/DPoP gateway exists. No HTTP implementation was invented to force passes.

---

## 8. Support authorization results

Evidence: `D_support_results.json`

SQL-function validation against `dcmp_security.open_support_session` / `verify_support_signature`:

| ID  | Scenario                            | Result                                        |
| --- | ----------------------------------- | --------------------------------------------- |
| D1  | Valid signed SSA                    | **PASSED**                                    |
| D2  | Invalid signature                   | **PASSED**                                    |
| D3  | Modified organization ID            | **PASSED**                                    |
| D4  | Modified grant ID                   | **PASSED**                                    |
| D5  | Modified admin ID                   | **PASSED**                                    |
| D6  | Expired grant                       | **PASSED**                                    |
| D7  | Revoked grant                       | **PASSED**                                    |
| D8  | Unapproved request                  | **PASSED**                                    |
| D9  | Expired SSA                         | **PASSED**                                    |
| D10 | Wrong issuer                        | **PASSED**                                    |
| D11 | Wrong audience                      | **PASSED**                                    |
| D12 | Invalid algorithm                   | **PASSED**                                    |
| D13 | Replayed JTI                        | **PASSED**                                    |
| D14 | Arbitrary GUC forgery               | **PASSED** — `verify_support_signature=false` |
| D15 | Missing/invalid DPoP where required | **NOT RUN** — gateway absent                  |
| D16 | Admin identity via trusted gateway  | **NOT RUN** — gateway absent                  |

End-to-end gateway authentication is **not** claimed from SQL tests alone.

---

## 9. AES-256-GCM / AAD results

Evidence: `E_aes_gcm_results.json`

Standalone **validation harness** (not production AuthModule). Canonical AAD prefix `dcmp-refresh-aad-v1`. 96-bit IV / 128-bit tag verified. Keys and plaintext tokens are not written to evidence.

| ID                                | Result                                |
| --------------------------------- | ------------------------------------- |
| E1 Encrypt/decrypt                | **PASSED**                            |
| E2 Wrong key                      | **PASSED**                            |
| E3 Modified ciphertext            | **PASSED**                            |
| E4 Modified tag                   | **PASSED**                            |
| E5 Modified IV                    | **PASSED**                            |
| E6 Incorrect AAD                  | **PASSED**                            |
| E7 Different org in AAD           | **PASSED**                            |
| E8 Different session in AAD       | **PASSED**                            |
| E9 Different token hash in AAD    | **PASSED**                            |
| E10 Different DPoP jkt in AAD     | **PASSED**                            |
| E11 Expired record policy         | **PASSED**                            |
| E12 Keys not stored in PostgreSQL | **PASSED** (`encryption_key_id` only) |
| E-IV / E-TAG / E-IV-RND           | **PASSED**                            |

---

## 10. DB-SEC-001 through DB-SEC-101 coverage matrix

Evidence: `F_coverage_matrix.json`, `F_coverage_matrix.md`

| Execution status | Count  |
| ---------------- | ------ |
| PASSED           | **54** |
| FAILED           | **0**  |
| BLOCKED          | **0**  |
| NOT RUN          | **47** |
| NOT APPLICABLE   | **0**  |

PASSED includes Phase 2.1.13 SQL/catalog evidence plus newly executed 2.1.14 concurrency, RedisSim, SSA SQL, AES, and jkt-binding cases. NOT RUN covers missing HTTP/DPoP gateway, full schema entities, and unimplemented SQL scenarios.

---

## 11. Failed and blocked tests

- **FAILED this phase:** none among executed harness cases.
- **BLOCKED:** none as execution status (environment was startable).
- **Prior Phase 2.1.13 BLOCKED items for 071/072:** cleared by this phase’s multi-connection harness.

---

## 12. Remaining implementation gaps

1. Full **63-entity / 7-stage** DDL not applied to `dcmp_validation`.
2. **Auth HTTP gateway + RFC 9449 DPoP** verifier not implemented → DB-SEC-018/019 and related NOT RUN.
3. **Real Redis** not available → Group B is simulated only.
4. Production AuthModule encryption service not in repo (E is a validation harness).
5. Remaining ~47 DB-SEC scenarios without harnesses (tenant DML, composite FKs, Stages 2–6, etc.).
6. Independent security review still required before Phase 2.2.

---

## 13. Security risks

| Risk                                            | Severity                    | Notes                                                         |
| ----------------------------------------------- | --------------------------- | ------------------------------------------------------------- |
| Refresh recovery without DPoP admission control | High (until gateway exists) | PG path validated; proof crypto not enforced in HTTP          |
| Redis assumed durable by future implementers    | Medium                      | ADRs + tests show PG authoritative; real Redis still untested |
| Partial schema                                  | Medium                      | RLS/concurrency proven only on Stage 1 security subset        |
| Support SSA HMAC secret in validation DB        | Low (disposable only)       | Validation key material; not for production                   |

---

## 14. Evidence file locations

```
infrastructure/database-validation/evidence/phase-2.1.14/
  00_environment.json
  00_run_summary.json
  A_concurrency_results.json
  B_redis_sim_results.json
  C_dpop_results.json
  D_support_results.json
  E_aes_gcm_results.json
  F_coverage_matrix.json
  F_coverage_matrix.md
```

Report: `doc/PHASE_2_1_14_CONCURRENCY_AND_SECURITY_INTEGRATION_VALIDATION_REPORT.md`

---

## 15. Recommended next steps

1. Implement Auth refresh gateway with DPoP (steps 1 and 3) and re-run Group C as real integration.
2. Stand up a disposable Redis for real cache-failure tests (keep PG authoritative).
3. Apply full Stage 1–7 schema to a disposable DB and expand DB-SEC NOT RUN cases.
4. Promote AES harness into production AuthModule with Vault-managed keys.
5. Commission independent security review.
6. **Do not start Phase 2.2** until the above and explicit owner authorization.

---

## 16. Final validation decision

### Distinction of validation layers

| Layer                                   | Status                                              |
| --------------------------------------- | --------------------------------------------------- |
| PostgreSQL SQL validation (subset)      | Carried forward PASSED from 2.1.13 + SSA extensions |
| Multi-connection concurrency validation | **PASSED** (executed)                               |
| Redis integration                       | **SIMULATED only** — not real Redis                 |
| DPoP application/gateway integration    | **NOT RUN** (2 DB-level checks PASSED)              |
| Support authorization integration       | **SQL PASSED**; gateway E2E **NOT RUN**             |
| AES-GCM application-layer validation    | **PASSED** (harness, not production module)         |
| Full database schema validation         | **NOT RUN**                                         |

### Decision

# VALIDATION PARTIAL — BLOCKED

Phase 2.2 remains **blocked** pending outstanding schema validation, real Redis/DPoP gateway integration testing, remaining DB-SEC coverage, independent security review, and **explicit authorization**.
