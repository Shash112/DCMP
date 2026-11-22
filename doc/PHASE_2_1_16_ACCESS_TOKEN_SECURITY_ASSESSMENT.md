# DCMP Phase 2.1.16 — Access-Token Security Assessment

**Date:** November 22, 2026  
**Scope:** HS256 access-token scaffold in `AuthService` (Phase 2.1.15/16)  
**Change in this phase:** Documented only — token format **not** silently changed

---

## 1. Current scaffold

| Claim / property   | Current behavior                                                               |
| ------------------ | ------------------------------------------------------------------------------ |
| Algorithm          | **HS256** (symmetric)                                                          |
| Issuer (`iss`)     | **Not set**                                                                    |
| Audience (`aud`)   | **Not set**                                                                    |
| Subject (`sub`)    | User id                                                                        |
| Organization       | Custom claim `orgId`                                                           |
| Session            | Custom claim `sid`                                                             |
| Roles              | Custom claim `roles[]`                                                         |
| Type               | Custom claim `type: 'access'`                                                  |
| Issued-at / expiry | `iat` + `exp` via jose (`15m` default)                                         |
| DPoP confirmation  | **`cnf.jkt` not present**                                                      |
| Signing key        | `JWT_ACCESS_SECRET` / config; refuses `dev_` prefix when `NODE_ENV=production` |

Token type returned to clients remains `Bearer` (API contract from Phase 2.1.15).

---

## 2. Architecture expectation (DPoP-bound access tokens)

Phase 2.1 design intent for protected APIs:

1. Access tokens should be **sender-constrained** with `cnf.jkt` matching the DPoP proof key thumbprint used at login/refresh.
2. Protected resources must verify: JWT signature + `exp` + `type` + org/session membership + **DPoP proof** with `ath` (access-token hash) and matching `jkt` ↔ `cnf.jkt`.
3. Preferred production algorithm: **asymmetric** (e.g. ES256) with rotatable JWKS — not long-lived shared HS256 secrets.

The current HS256 Bearer scaffold is a **compatibility placeholder** for `/auth/me` and early integration only.

---

## 3. Verification requirements (target)

| Check                      | Required                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| Signature / JWKS           | Yes                                                                                         |
| `iss` / `aud`              | Yes (fixed platform values)                                                                 |
| `exp` / `nbf` / clock skew | Yes                                                                                         |
| `sub` + `orgId` + `sid`    | Yes; org must match verified session                                                        |
| `cnf.jkt`                  | Yes when adopting DPoP-bound access tokens                                                  |
| Request DPoP               | Yes on protected mutating/read APIs that hold sensitive data                                |
| Revocation                 | Session revocation must invalidate access use (short TTL + `sid` denylist or introspection) |

---

## 4. Revocation strategy

- **Primary:** short access TTL (≤15m) + refresh rotation; logout/reuse revokes session in PostgreSQL.
- **Secondary:** optional `sid` denylist in Redis (non-authoritative cache) with fail-closed policy for high-risk routes.
- **Not sufficient alone:** trusting unexpired HS256 without session check.

---

## 5. Compatibility impact if changed

Introducing `cnf.jkt`, `iss`/`aud`, or switching to ES256 / `DPoP` token type would be an **API contract change** requiring:

- Client updates (Flutter / API consumers)
- Contract package version bump
- Explicit migration notes

**Phase 2.1.16 decision:** retain HS256 Bearer scaffold; track DPoP-bound access tokens as a follow-on hardening item before Phase 2.2 production authorization.

---

## 6. Residual risk

| Risk                                | Severity                     | Status                                                 |
| ----------------------------------- | ---------------------------- | ------------------------------------------------------ |
| Shared HS256 secret compromise      | High (prod if misconfigured) | Mitigated by production secret refusal; still scaffold |
| Access token not sender-constrained | High for bearer theft        | **Open** — documented, not fixed this phase            |
| Missing iss/aud                     | Medium                       | Open                                                   |
| No session introspection on `/me`   | Medium                       | `/me` verifies JWT only                                |

---
