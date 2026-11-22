# Phase 2.1.21 — SSA Key Management Report

## Implemented

- `SsaSigningProvider` interface with `LocalSsaSigningProvider` and `KmsSsaSigningProvider`
- Gateway mint uses injected signer (`SupportSessionService.mintAssertion`)
- KMS path: `GenerateMac` / `VerifyMac` (HMAC_SHA_256); key never exported
- Attested SQL open: `open_support_session_attested` + GUC `app.ssa_kms_attested` (additive Stage-1 SQL)
- Local path unchanged: seed `internal_keys` + classic `open_support_session`

## Live AWS results

**NOT_RUN** (same blocker as access-token KMS).

## Compatibility

Phase 2.1.20 SSA HTTP E2E re-run with local signer: **16/16 PASSED** (including mint/open/replay/revoke).
