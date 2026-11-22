# Phase 2.1.23 — Multi-Key Live AWS Provisioning Plan (AWAITING APPROVAL)

**Status (at authoring):** AWAITING APPROVAL — not executed in 2.1.23.

**Addendum (Phase 2.1.24):** Prior keys and IAM updates were completed by the owner outside this document’s execution. Live application validation is in `doc/PHASE_2_1_24_LIVE_MULTI_KEY_ROTATION_REPORT.md`. This plan remains historical; do not re-run CreateKey.

## Why this is needed

Live multi-key rotation validation for access-token ECC and SSA HMAC requires **additional** KMS keys in account `980921756876` / `ap-south-1`. Only one key of each purpose exists today. Application code already supports verify lists; live proof needs a second key each.

Refresh-master multi-CMK live proof similarly needs a second symmetric CMK and historical envelopes wrapped under it. CiphertextBlob already carries wrapping-key metadata; `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS` is a soft allowlist only.

## Proposed non-prod keys (do not create until approved)

| Purpose | Spec | Alias (suggested) | Env after create |
|---------|------|-------------------|------------------|
| Access-token verify (prior) | `ECC_NIST_P256` / `SIGN_VERIFY` | `alias/dcmp-nonprod-access-token-v0` | Add UUID/ARN to `DCMP_KMS_ACCESS_TOKEN_VERIFY_KEY_IDS`; keep active in `DCMP_KMS_ACCESS_TOKEN_KEY_ID` |
| SSA HMAC verify (prior) | `HMAC_256` / `GENERATE_VERIFY_MAC` | `alias/dcmp-nonprod-ssa-hmac-v0` | Add to `DCMP_KMS_SSA_HMAC_VERIFY_KEY_IDS` |
| Refresh master (prior) | Symmetric CMK for `GenerateDataKey`/`Decrypt` | `alias/dcmp-nonprod-refresh-master-v0` | Encrypt sample under v0, then set active to current master and put v0 in `DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS` |

## IAM

Confirm existing `dcmp-kms-dev` (or workload role) already has `kms:GetPublicKey`, `Sign`, `GenerateMac`, `VerifyMac`, `GenerateDataKey`, `Decrypt` on the **new** key ARNs (or via alias). Prefer extending the same key policy pattern as the three existing keys. **Do not broaden to `kms:*`.**

## Validation sequence (after approval)

1. Create keys + aliases only (no disable/delete of existing keys).
2. Mint one access token under the new “prior” ECC key (temporarily active), then flip active to current key and set prior in `VERIFY_KEY_IDS` — prove JWKS contains both and old JWT verifies.
3. GenerateMac under prior HMAC, flip active, prove VerifyMac via verify list.
4. GenerateDataKey under prior refresh CMK, store envelope, flip active, prove Decrypt + allowlist.
5. Update evidence under `infrastructure/database-validation/evidence/phase-2.1.23/`.

## Explicit non-goals until further approval

- Production keys
- Key deletion / disable of current non-prod keys
- Automatic key rotation policies
- Schema changes

**Stop here until owner approves CreateKey for the three prior keys above.**
