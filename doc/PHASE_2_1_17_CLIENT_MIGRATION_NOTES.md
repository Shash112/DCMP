# DCMP Phase 2.1.17 — Client Migration Notes (Access Token / DPoP)

**Breaking change** relative to Phase 2.1.15/16 HS256 Bearer scaffold.

## What changed

| Item             | Before                 | After                                                     |
| ---------------- | ---------------------- | --------------------------------------------------------- |
| Access-token alg | HS256                  | **ES256** (`kid` in header)                               |
| `tokenType`      | `Bearer`               | **`DPoP`**                                                |
| Authorization    | `Bearer <AT>`          | **`DPoP <AT>`**                                           |
| Protected proof  | Not required for `/me` | **DPoP header required** with `ath`                       |
| Claims           | no iss/aud/cnf         | **`iss`, `aud`, `cnf.jkt`, `jti`, `nbf`, `sid`, `orgId`** |

## Flutter / mobile

1. Persist the ES256 DPoP keypair created (or reused) at login — same key used for refresh proofs.
2. On login/refresh response, read `tokenType: DPoP` and store access + refresh tokens securely.
3. For every protected API call:
   - `Authorization: DPoP <access_token>`
   - `DPoP: <proof JWT>` with `htm`, `htu`, `iat`, `jti`, and **`ath`** = BASE64URL(SHA-256(ASCII(access_token)))
4. Honor `DPoP-Nonce` response headers; include `nonce` in subsequent proofs when challenged.
5. Do not attempt to verify access tokens with a shared HS256 secret — clients treat AT as opaque; servers verify via JWKS.
6. Optional: cache `GET /api/v1/auth/.well-known/jwks.json` only if a client-side JWT inspection feature is added (not required for normal API use).

## Retiring HS256

- Backend **rejects** `Authorization: Bearer` on DPoP-bound routes.
- No production dual-accept mode.
- Any stored HS256 tokens from earlier scaffolds are invalid immediately after deploy.

## Contracts

- `@dcmp/shared-types` `AuthTokens.tokenType` is `'DPoP'`.
- New error codes: `LOGIN_ORGANIZATION_REQUIRED`, `ACCESS_TOKEN_INVALID`.
