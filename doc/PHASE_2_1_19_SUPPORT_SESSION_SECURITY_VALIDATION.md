# DCMP Phase 2.1.19 — Support-Session Security Validation

**Database:** `dcmp_full_schema_validation` (not Stage-1-only `dcmp_validation`)  
**Harness:** `tests/phase-2.1.19/test_d_support_ssa.py`  
**Evidence:** `evidence/phase-2.1.19/D_support_ssa_results.json`  
**Key material:** TEST-ONLY (`val-key-fullschema-1`) — not for production

---

## 1. SQL path implemented

| Object                                                               | Status                                   |
| -------------------------------------------------------------------- | ---------------------------------------- |
| `dcmp_security.constant_time_eq`                                     | Implemented                              |
| `dcmp_security.verify_support_signature`                             | Implemented                              |
| `dcmp_security.open_support_session`                                 | Implemented (full-schema column mapping) |
| `dcmp_security.b64url_to_bytea`                                      | Implemented (JWT padding)                |
| Platform-admin SELECT policies gated by `verify_support_signature()` | Applied to tenant-owned tables           |
| DEFINER SELECT policies on support request/grant                     | S12                                      |

---

## 2. Executed results

| Test ID                               | Result                           |
| ------------------------------------- | -------------------------------- |
| DB-SEC-062 constant_time_eq           | **PASSED**                       |
| DB-SEC-SSA-001 open+verify happy path | **PASSED** (`own>=1`, `other=0`) |
| DB-SEC-009 forged support GUC         | **PASSED**                       |
| DB-SEC-041 invalid iss                | **PASSED**                       |
| DB-SEC-010 org claim mismatch         | **PASSED**                       |
| DB-SEC-013 expired grant              | **PASSED**                       |
| DB-SEC-034 JTI replay                 | **PASSED**                       |
| DB-SEC-058 admin without SSA          | **PASSED**                       |
| DB-SEC-SSA-GATEWAY HTTP minting       | **NOT_RUN**                      |

Summary: **8 PASSED / 1 NOT_RUN / 0 FAILED**

---

## 3. Explicit application-layer gap

SQL validates assertion consumption, grant expiry, tenant binding, and signature GUCs.

The Nest/platform gateway that **mints** HS256 SSAs, issues challenges, and drives customer approval UX is **not** re-validated as an HTTP E2E flow in this phase (`DB-SEC-SSA-GATEWAY` = NOT_RUN).

Support authorization is **not** a general platform-admin bypass: without a successful `open_support_session`, tenant SELECT policies return 0 rows.

---

## 4. Limitations

- Test HMAC secret only.
- Challenge/request/grant bootstrap is harness-owned SQL, not production APIs.
- Cross-transaction signature replay multi-conn scenarios beyond pool suite remain catalog NOT_RUN where not re-executed.
