# Phase 2.1.21 — Access-Token Key Management Report

## Implemented

- `KmsAccessTokenKeyProvider` (`apps/backend/src/modules/auth/crypto/kms-access-token-key.provider.ts`)
- DER↔JOSE helpers (`ecdsa-der-jose.ts`) — unit tested
- `AuthService.signAccess` uses `signCompactJwt` when KMS mode / `kmsSign`
- JWKS via `GetPublicKey` + `listVerificationJwks`
- Production refuses `LocalAccessTokenKeyProvider` without explicit lab override

## Live AWS results

**NOT_RUN.** No `DCMP_KMS_ACCESS_TOKEN_KEY_ID` configured. Observed AWS profile `farmerswing-prod` is not an approved disposable KMS lab; agent refused `CreateKey`.

## Local / unit

| Test                                          | Result                                |
| --------------------------------------------- | ------------------------------------- |
| DER↔JOSE round-trip verify                    | PASSED (`npm run test:auth:kms-unit`) |
| Prior Phase 2.1.20 HTTP ES256 with local keys | Still PASSED (regression)             |

## Rotation / outage

Documented and coded (`rotateForTest`, retire, `KMS_UNAVAILABLE` → 503). **Not demonstrated against live KMS.**
