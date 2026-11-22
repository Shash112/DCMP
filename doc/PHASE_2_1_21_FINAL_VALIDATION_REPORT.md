# Phase 2.1.21 — Final Validation Report

## Decision

**VALIDATION PARTIAL — BLOCKED**

Providers, fail-closed wiring, DER/JOSE conversion, SSA attested-open SQL, envelope schema, and safe failure-recovery tests are in place. **Actual AWS KMS integration was not executed** because no dedicated non-production KMS key IDs were configured, and the only available AWS profile (`farmerswing-prod`) is not an approved disposable lab for `CreateKey` / signing.

## AWS environment

| Item                                      | Value                                        |
| ----------------------------------------- | -------------------------------------------- |
| Profile observed                          | `farmerswing-prod` (credential chain works)  |
| Region default                            | `ap-south-1` / aliases listed in `us-east-1` |
| DCMP_KMS_* key IDs                        | **Unset**                                    |
| Keys created this phase                   | **None** (refused)                           |
| Live Sign / GenerateMac / GenerateDataKey | **NOT_RUN**                                  |

## KMS key types (designed)

1. ECC_NIST_P256 — access-token ES256
2. HMAC_256 — SSA GenerateMac/VerifyMac
3. SYMMETRIC_DEFAULT — refresh envelope CMK

## Tests executed

| Suite                           | Result                          |
| ------------------------------- | ------------------------------- |
| `test:auth:kms-unit` (DER/JOSE) | 2 PASSED                        |
| `test:auth:failure`             | 4 PASSED + 1 NOT_RUN (KMS live) |
| `test:auth:redis` regression    | 16 PASSED                       |

## Key rotation / KMS outage

Implemented in code; **not demonstrated on live KMS**.

## Failure recovery

Safe variants of prior 2.1.20 NOT_RUN items PASSED with documented limitations (no Docker kill, no Nest mid-refresh process kill).

## Combined matrix

**499 PASSED / 64 NOT_RUN / 23 N/A / 0 FAILED**

## Outstanding NOT_RUN (KMS acceptance)

- DB-SEC-KMS-LIVE, AT-SIGN, AT-ROTATE, SSA-MAC, ENVELOPE, DENIED, THROTTLE

## Git

- Branch: `main`
- Working tree: **dirty**
- **No commit. No push.**

## Phase 2.2

Remains **blocked** until remaining security gates (including live non-prod KMS validation), Flutter DPoP migration, independent security review, and **explicit owner authorization**.
