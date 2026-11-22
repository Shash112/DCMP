# DCMP Phase 2.1.17 — Access-Token Architecture Decision

**Date:** November 22, 2026  
**Status:** Decision recorded before implementation  
**Builds on:** Phase 2.1.16 PostgreSQL AuthStore (validated)

---

## 1. Options compared

| Option | Signing | Sender constraint | Key mgmt | Fit for DCMP |
| ------ | ------- | ----------------- | -------- | ------------ |
| **A. HS256 Bearer** (current scaffold) | Shared secret | None — stolen token works | Secret distribution hard; rotation weak | Reject for production |
| **B. ES256 asymmetric + JWKS** | Server EC P-256 | None unless added | JWKS + `kid` rotation | Stronger than A but still bearer-stealable |
| **C. ES256 + DPoP `cnf.jkt`** (RFC 9449) | Server ES256 | Proof must match `cnf.jkt`; `ath` binds proof to AT | Same as B + client keypair | **Selected** |

---

## 2. Decision

**Adopt Option C:** asymmetrically signed (ES256) JWT access tokens with:

- Standard claims: `iss`, `aud`, `sub`, `iat`, `exp`, `nbf`, `jti`
- DCMP claims: `sid`, `orgId`, `roles`, `type: 'access'`
- Confirmation: `cnf.jkt` = JWK thumbprint of the client DPoP key established at login
- Response `token_type`: **`DPoP`** (RFC 9449 §6)
- Authorization scheme on protected resources: **`Authorization: DPoP <access_token>`** plus `DPoP` proof header

HS256 Bearer is **retired** for new issuance. No production legacy HS256 mode. Validation environments and clients must migrate explicitly (documented in the implementation report).

---

## 3. Signing and verification architecture

```
Login/Refresh (AuthService)
  → AccessTokenSigningKeyProvider.getActiveSigningKey()
  → SignJWT(...claims, cnf:{jkt}) header {alg:ES256, kid}
  → client receives accessToken + tokenType:DPoP

Protected API (DpopBoundAuthGuard)
  → Parse Authorization: DPoP <token>
  → jwtVerify with JWKS by kid (ES256 only)
  → Validate iss, aud, type, exp, nbf, cnf.jkt
  → validateDpopProof(+ accessToken → ath, expectedJkt=cnf.jkt)
  → Replay store (JTI) fail-closed
  → PostgreSQL session introspection (authoritative)
  → Attach VerifiedAuthContext
```

Refresh **re-binds** the same session `dpop_jkt`; new access tokens carry the same `cnf.jkt` as the session. Key change requires re-login (new session).

---

## 4. JWKS publication and key identification

| Item | Decision |
| ---- | -------- |
| Endpoint | `GET /api/v1/auth/.well-known/jwks.json` (and alias if needed) |
| Contents | Public EC P-256 JWKs only (`kty`,`crv`,`x`,`y`,`kid`,`use`,`alg`) |
| `kid` | Stable opaque id per key version (e.g. `access-es256:v1`) |
| Private keys | Never in JWKS, logs, or responses |
| Verification | Resource servers load JWKS (in-process provider for monolith) |

---

## 5. Key rotation

1. Add new key as active for signing; keep previous in JWKS for verification until all outstanding AT TTLs expire (+ skew).
2. Retire keys by removing from verification set after grace window.
3. Unknown/`kid` retired → reject signature.
4. Rotation must **not** invalidate unexpired tokens signed by previous still-published keys.
5. Refresh-response AES-GCM keys remain a **separate** provider (Phase 2.1.15); never reuse for access-token signing.

---

## 6. Issuer and audience

| Claim | Value (validation / configurable) |
| ----- | --------------------------------- |
| `iss` | `https://auth.dcmp.local` (override `DCMP_ACCESS_TOKEN_ISSUER`) |
| `aud` | `dcmp-api` (override `DCMP_ACCESS_TOKEN_AUDIENCE`) |

Strict match on verify. Production must set non-local issuer via config/secrets — never hardcode production private keys.

---

## 7. Token type and Authorization scheme

| Surface | Value |
| ------- | ----- |
| Token response `tokenType` / `token_type` | `DPoP` |
| Protected `Authorization` | `DPoP <access_token>` |
| Legacy `Bearer` | **Rejected** on protected routes after this phase |

---

## 8. DPoP confirmation binding

- At login: session stores `dpop_jkt`; AT includes `cnf.jkt` equal to that thumbprint.
- At protected call: proof JWK thumbprint MUST equal `cnf.jkt` AND session `dpop_jkt`.
- Proof MUST include `ath` = BASE64URL(SHA-256(ASCII(access_token))).

Stolen AT without client private key → authorization denied.

---

## 9. Client compatibility

**Breaking change** relative to Phase 2.1.15/16 Bearer scaffold:

1. Clients must send `Authorization: DPoP …` and a per-request DPoP proof with `ath`.
2. Flutter (and others) must persist the DPoP keypair bound at login.
3. Contract packages update `tokenType: 'DPoP'`.
4. Short migration window: no silent dual-accept of Bearer in production builds.

Flutter code is **not** modified in 2.1.17 unless a focused compatibility harness is required; migration is documented for a later client phase.

---

## 10. Token revocation

| Mechanism | Role |
| --------- | ---- |
| Short AT TTL (≤ 15 minutes) | Limits stolen-token window |
| PostgreSQL session revoke (logout / reuse) | **Authoritative** — introspection fails |
| Redis `sid` denylist | Optional non-authoritative; must not replace PG |
| Refresh idempotency invalidation | Blocks credential recovery |

JWT signature alone is **insufficient**.

---

## 11. Session verification

On every protected request (policy: **always** for `/auth/me` and DPoP-bound guards):

1. Session exists for `sid` + `orgId`
2. `sub` matches `user_id`
3. `is_active`, not expired, not revoked
4. Session `dpop_jkt` matches `cnf.jkt`

No caching as authority in this phase. If a future cache is added, document TTL ≤ AT lifetime and invalidate on logout/reuse.

---

## 12. API migration strategy

1. Ship contract + backend together (this phase).
2. Document Flutter changes (keypair storage, DPoP Authorization, nonce, JWKS unused on client for AT verify).
3. Reject HS256 and `Bearer` on protected APIs immediately in Nest (no insecure production legacy mode).
4. Memory + PostgreSQL HTTP suites updated; evidence separated.

---

## 13. Login identity (related decision)

Email uniqueness in the validation schema is **organization-scoped** (composite), not globally unique. Login MUST:

- Prefer explicit `organizationId` when supplied (membership verified).
- If omitted and multiple active matches exist → reject with non-enumerating error.
- Never let DEFINER `LIMIT 1` silently pick an arbitrary tenant.

---

## 14. Production key management

| Provider | Status |
| -------- | ------ |
| `AccessTokenSigningKeyProvider` interface | Required |
| `LocalAccessTokenKeyProvider` (ES256 test keys) | Implemented for validation |
| AWS KMS / Secrets Manager | Interface only — **NOT RUN** |

Production refuses local provider unless explicitly allowed (same pattern as refresh cipher).
