# Phase 2.1.21 — AWS KMS Architecture

## Decision summary

Three **distinct** KMS keys (never shared across purposes):

| Purpose              | KMS key type                              | App surface                                                                                |
| -------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| Access-token signing | Asymmetric **ECC_NIST_P256** (SignVerify) | `KmsAccessTokenKeyProvider` — `Sign` ECDSA_SHA_256, DER→JOSE R\|\|S, `GetPublicKey` → JWKS |
| SSA HS256            | Symmetric **HMAC_256**                    | `KmsSsaSigningProvider` — `GenerateMac` / `VerifyMac` (key **never exported**)             |
| Refresh idempotency  | Symmetric **SYMMETRIC_DEFAULT** CMK       | `KmsRefreshEnvelopeProvider` — `GenerateDataKey(AES_256)` + local AES-256-GCM + AAD        |

Local TEST-ONLY providers remain for development/validation. **Production refuses local providers** unless `AUTH_ALLOW_LOCAL_KEYS` (lab-only).

## Credential chain

1. EC2/ECS/EKS workload IAM role (preferred)
2. Other assumed IAM role via default AWS SDK credential provider chain
3. Development-only shared credentials / profile — **never hardcoded**

Config keys (identifiers only — no secret material):

- `AUTH_CRYPTO_DRIVER=kms|local`
- `DCMP_KMS_REGION`
- `DCMP_KMS_ACCESS_TOKEN_KEY_ID` (+ optional `DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS`)
- `DCMP_KMS_SSA_HMAC_KEY_ID` (+ optional verify list)
- `DCMP_KMS_REFRESH_MASTER_KEY_ID` (+ optional verify list)

Startup fails closed if driver=kms and any of the three IDs is missing, or if the three IDs are not distinct.

## Access-token ES256

1. Active key signs via KMS `Sign` over compact JWT signing input.
2. Signature converted with `derToJoseEs256`.
3. Verification uses published public JWK (`GetPublicKey`); private key never leaves KMS.
4. Rotation: new key becomes active signer; prior kids remain in JWKS until retired.

## SSA HMAC (non-exportable)

SQL `open_support_session` historically verifies HS256 using `internal_keys.key_secret`. A true KMS HMAC key **cannot** be exported into PostgreSQL.

**ADR:** Gateway performs `VerifyMac`, sets transaction-local `app.ssa_kms_attested=true`, then calls `dcmp_security.open_support_session_attested`, which still enforces JTI, challenge, grant, org, and temporal claims. This is **not** a platform-admin bypass.

Local TEST-ONLY mode continues to use `open_support_session` + seeded `internal_keys`.

## Refresh envelope encryption

1. `GenerateDataKey` → plaintext DEK (memory only) + `CiphertextBlob`.
2. Encrypt payload with AES-256-GCM; AAD = canonical refresh fields.
3. Persist ciphertext, IV, tag, `encryption_key_id`, and `encrypted_data_key` (nullable column added in Stage-1).
4. Decrypt: KMS `Decrypt` on wrapped DEK (encryption context bound to org/session) → GCM open → zeroize DEK.
5. Never store plaintext DEKs; never fall back to local keys in KMS mode.

## Fail-closed

| Failure                       | Behavior                                                |
| ----------------------------- | ------------------------------------------------------- |
| KMS unavailable / throttle    | Throw `KMS_UNAVAILABLE:*` → HTTP 503 crypto unavailable |
| Permission denied             | Same fail-closed path                                   |
| Local providers in production | Startup refusal                                         |
| Missing / duplicated key IDs  | Startup refusal                                         |

## Provisioning (documentation only)

Create **three** keys in a **non-production** account; alias e.g. `alias/dcmp-val-access-es256`, `alias/dcmp-val-ssa-hmac`, `alias/dcmp-val-refresh-cmk`. Grant the workload role `kms:Sign`, `kms:GetPublicKey`, `kms:GenerateMac`, `kms:VerifyMac`, `kms:GenerateDataKey`, `kms:Decrypt` scoped to those ARNs. **Do not** schedule deletion during validation.
