# Phase 2.1.20 — SSA Gateway HTTP E2E Report

## Summary

The support-session assertion **application gateway** was completed and exercised over NestJS HTTP against Stage-1 `dcmp_validation` (PostgreSQL 16.10). Phase 2.1.19 SQL SSA tests remain valid on `dcmp_full_schema_validation`; this phase closes the prior **NOT_RUN** gateway minting gap.

## Gateway routes (`/api/v1/auth/support/*`)

1. `POST /requests` — platform operator access request  
2. `POST /approve` — customer approval → time-limited grant  
3. `POST /challenges` — single-use challenge  
4. `POST /assertions` — mint HS256 SSA (**TEST-ONLY** key)  
5. `POST /sessions/open` — `open_support_session` + `verify_support_signature`  
6. `POST /grants/revoke` — revoke grant  

Implementation: `support-session.service.ts` / `support-session.controller.ts`.

## Flow validated

| Step | Result |
|------|--------|
| Request + customer approval + grant | PASSED |
| Challenge issuance | PASSED |
| Assertion mint (TEST-ONLY) | PASSED |
| `open_support_session` success + verify | PASSED (DB-SEC-SSA-GATEWAY) |
| Replay denied | PASSED (DB-SEC-SSA-REPLAY) |
| Revoked grant denied | PASSED (DB-SEC-SSA-REVOKED) |

## Schema note

Stage-1 challenge table uses `challenge_id` PK (no surrogate `id`/`nonce`). Gateway detects columns via `information_schema` and inserts the Stage-1 shape. Additive SQL `sql/phase-2.1.20_ssa_b64url_pad_stage1.sql` pads base64url JWT segments for PostgreSQL `decode` (preserves DB; no recreate).

## Security constraints honored

- No general platform-admin bypass.
- Support access remains scoped, time-limited, customer-approved, auditable (best-effort `security_events` insert).
- Signing material labeled `TEST-ONLY`; production KMS/Vault **not** claimed.

## Limitations

- Gateway E2E ran on `dcmp_validation` (Stage-1 SSA). Full-schema HTTP E2E against `dcmp_full_schema_validation` was not duplicated in this phase (SQL path already PASSED in 2.1.19).
- Cross-tenant support SELECT isolation after open was covered in 2.1.19 SQL harness; HTTP suite focuses on mint/open/deny paths.
