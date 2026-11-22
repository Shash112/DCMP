# CI Failure Diagnosis — Commit `2a0d09a`

| Field                         | Value                                                                    |
| ----------------------------- | ------------------------------------------------------------------------ |
| Repository                    | `Shash112/DCMP`                                                          |
| Commit                        | `2a0d09aa6d6e70f190bcb1275fe4c6ea31b9d261` (`2a0d09a`)                   |
| Branch                        | `main`                                                                   |
| Workflow run                  | [45067198696](https://github.com/Shash112/DCMP/actions/runs/45067198696) |
| Parent (last green on `main`) | `dbc80b34a93e3890f0fe58088a93431c8f9d00aa`                               |
| Diagnosis date                | 2026-11-23                                                               |
| Scope                         | Diagnose only — no code, CI, dependency, git, or AWS changes             |

---

## 1. Failure summary

| Job                               | Conclusion | First failing step                                    | Downstream steps                                  |
| --------------------------------- | ---------- | ----------------------------------------------------- | ------------------------------------------------- |
| Lint & Typecheck                  | **FAILED** | Check Formatting (Prettier) — `pnpm run format:check` | ESLint, `build:packages`, `typecheck` **skipped** |
| Build NestJS & Next.js Apps       | **FAILED** | Build Applications — `pnpm run build:apps`            | — (packages build succeeded)                      |
| Analyze & Test Flutter Mobile App | **PASSED** | —                                                     | —                                                 |

Two independent root causes:

1. **Lint job:** Prettier style drift on files introduced/changed by `2a0d09a` (auth + Phase 2.1 docs + lockfile + infra). ESLint/typecheck never ran.
2. **Build job:** NestJS (`@dcmp/backend`) TypeScript compile errors against `jose@6.2.18` / Node `lib` settings. Next.js apps compile successfully.

---

## 2. Log access limitations

| Method                                  | Result                                                                                                    |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `gh run view 45067198696`               | **Unavailable** — GitHub CLI (`gh`) not installed / not on PATH                                           |
| `GET .../actions/runs/45067198696/logs` | **403 Forbidden** (unauthenticated; full job logs require auth)                                           |
| Public Jobs / Annotations API           | Step conclusions available; annotations only report `Process completed with exit code 1` (no stderr body) |

Exact error text below comes from **local reproduction** using the same pnpm scripts and pnpm version as CI (`9.15.9`). Local Node is `v26.13.0`; CI uses Node `20`. The observed TypeScript errors are type-resolution issues and are not Node-major-specific.

---

## 3. Workflow review

Source: `.github/workflows/ci.yml`

### Lint & Typecheck

```
pnpm install --frozen-lockfile
→ pnpm run format:check
→ pnpm run lint
→ pnpm run build:packages
→ pnpm run typecheck
```

Root scripts (`package.json`):

- `format:check`: `prettier --check "**/*.{ts,tsx,js,json,md,yaml,yml}"`
- `lint`: `pnpm -r --filter=!mobile-app run lint`
- `build:packages`: `pnpm --filter "./packages/*" run build`
- `typecheck`: `pnpm run build:packages && pnpm -r --filter=!mobile-app run typecheck`

**Ordering:** Correct for a serial gate. Prettier failure correctly blocks ESLint/typecheck. No evidence of wrong package filters for this failure mode.

### Build NestJS & Next.js Apps

```
pnpm install --frozen-lockfile
→ pnpm run build:packages
→ pnpm run build:apps   # pnpm --filter "./apps/*" run build
```

**Ordering:** Correct — shared packages built before apps. CI confirmed `build:packages` succeeded; failure is isolated to app build (`nest build` in `@dcmp/backend`).

### `.prettierignore`

Ignores `node_modules`, `dist`, `build`, `.next`, `out`, `coverage`, `apps/mobile-app`, some `docs/*` binaries. Does **not** ignore `pnpm-lock.yaml`, `doc/**`, or generated Prisma clients. CI therefore formats the lockfile and all Phase 2.1 markdown under `doc/`.

---

## 4. Job A — Lint & Typecheck

### Exact failing command

```bash
pnpm run format:check
# → prettier --check "**/*.{ts,tsx,js,json,md,yaml,yml}"
```

Exit code `1`. Message:

```text
Code style issues found in 91 files. Run Prettier with --write to fix.
```

(Local working tree includes untracked `packages/database/`. CI checkout of `2a0d09a` does **not** include that directory.)

### CI-relevant scope (tracked at `HEAD` / `2a0d09a`)

**68 tracked files** fail Prettier. Categories:

| Category                    | Count (approx.) | Examples                                                                                 |
| --------------------------- | --------------- | ---------------------------------------------------------------------------------------- |
| Auth NestJS sources + tests | ~28             | `apps/backend/src/modules/auth/**/*.ts`                                                  |
| Phase 2.1 docs under `doc/` | ~36             | `doc/PHASE_2_1_*.md`                                                                     |
| Infra / ops notes           | 2               | `infrastructure/docker/docker-compose.pg16-validation.yml`, `REDIS_OPERATIONAL_NOTES.md` |
| Lockfile                    | 1               | `pnpm-lock.yaml`                                                                         |

Full tracked list (CI-equivalent):

```text
apps/backend/src/modules/auth/__tests__/access-token-security.integration.spec.ts
apps/backend/src/modules/auth/__tests__/auth-gateway.integration.spec.ts
apps/backend/src/modules/auth/__tests__/phase-2.1.20-redis-http.integration.spec.ts
apps/backend/src/modules/auth/__tests__/phase-2.1.21-failure-recovery.integration.spec.ts
apps/backend/src/modules/auth/__tests__/phase-2.1.22-live-kms.integration.spec.ts
apps/backend/src/modules/auth/__tests__/phase-2.1.23-persistence-rotation.integration.spec.ts
apps/backend/src/modules/auth/__tests__/phase-2.1.24-live-multikey-rotation.integration.spec.ts
apps/backend/src/modules/auth/__tests__/postgres-auth.integration.spec.ts
apps/backend/src/modules/auth/__tests__/set-postgres-env.ts
apps/backend/src/modules/auth/__tests__/set-redis-postgres-env.ts
apps/backend/src/modules/auth/auth.controller.ts
apps/backend/src/modules/auth/auth.service.ts
apps/backend/src/modules/auth/crypto/auth-crypto.registration.ts
apps/backend/src/modules/auth/crypto/kms-access-token-key.provider.ts
apps/backend/src/modules/auth/crypto/kms-config.ts
apps/backend/src/modules/auth/crypto/kms-refresh-envelope.provider.ts
apps/backend/src/modules/auth/crypto/kms-wrapping-key-allowlist.ts
apps/backend/src/modules/auth/crypto/local-access-token-key.provider.ts
apps/backend/src/modules/auth/crypto/local-test-key.provider.ts
apps/backend/src/modules/auth/crypto/ssa-signing.provider.ts
apps/backend/src/modules/auth/dpop/dpop.validator.ts
apps/backend/src/modules/auth/errors/auth.errors.ts
apps/backend/src/modules/auth/guards/dpop-bound-auth.guard.ts
apps/backend/src/modules/auth/persistence/auth-store.port.ts
apps/backend/src/modules/auth/persistence/memory-auth.store.ts
apps/backend/src/modules/auth/persistence/pg.pool.ts
apps/backend/src/modules/auth/persistence/postgres-auth.store.ts
apps/backend/src/modules/auth/support/support-session.service.ts
doc/PHASE_2_1_1_ARCHITECTURAL_DECISION_REGISTER.md
doc/PHASE_2_1_11_FINAL_SECURITY_OWNERSHIP_AND_IDEMPOTENCY_REVIEW.md
… (remaining PHASE_2_1_* docs listed by local prettier) …
doc/PHASE_2_1_25_KMS_SECURITY_REMEDIATION_REPORT.md
doc/PHASE_2_1_DATABASE_DESIGN_REVIEW.md
infrastructure/database-validation/REDIS_OPERATIONAL_NOTES.md
infrastructure/docker/docker-compose.pg16-validation.yml
pnpm-lock.yaml
```

### Local-only (not CI)

Untracked `packages/database/**` (23 generated/client + `package.json` paths) also fail Prettier locally. They are **not** in commit `2a0d09a` and did not cause this CI run. Preserve that directory; do not commit it as part of a formatting fix unless intentionally promoted.

### ESLint / typecheck

Not executed in CI because Prettier failed first. Local `nest build` (Job B) already surfaces TypeScript errors that `typecheck` would almost certainly hit for `@dcmp/backend`. ESLint status is **unknown** until formatting is fixed and the lint step is re-run.

### Root cause (Lint)

**Newly introduced formatting debt** from the Phase 2.1.24–2.1.25.1 checkpoint commit. Auth sources, Phase 2.1 markdown, infra YAML, and a large `pnpm-lock.yaml` rewrite were committed without satisfying `prettier --check`.

**Evidence (new vs pre-existing):**

- Prior `main` run on parent `dbc80b3` concluded **success**.
- Auth crypto / KMS / many `doc/PHASE_2_1_*` paths did not exist (or were not on `main`) at the green parent; `2a0d09a` added them.
- Failure is Prettier only — not a logic or dependency-install failure (`pnpm install --frozen-lockfile` succeeded).

**Not caused by:** workspace dependency ordering, Prisma package exports in CI, missing env vars, or Flutter tooling.

---

## 5. Job B — Build NestJS & Next.js Apps

### Exact failing command

```bash
pnpm run build:apps
# → pnpm --filter "./apps/*" run build
# → apps/backend: nest build   ← fails
# → apps/customer-web / apps/platform-admin: next build  ← compile OK locally
```

### Package affected

`@dcmp/backend` (`apps/backend`). Next.js apps compiled successfully in local reproduction.

### Exact compiler errors (local `nest build`)

```text
src/modules/auth/crypto/access-token-key.provider.ts:1:32 - error TS2305:
  Module '"jose"' has no exported member 'KeyLike'.
  import type { JWK, JWTPayload, KeyLike } from 'jose';

src/modules/auth/crypto/kms-access-token-key.provider.ts:8:64 - error TS2305:
  Module '"jose"' has no exported member 'KeyLike'.
  import { exportJWK, importJWK, type JWK, type JWTPayload, type KeyLike } from 'jose';

src/modules/auth/dpop/dpop.validator.ts:190:19 - error TS2304:
  Cannot find name 'CryptoKey'.
  let privateKey: CryptoKey | Uint8Array;
```

`Found 3 error(s).` → `nest build` exit 1 → recursive `build:apps` fails.

### Root cause (Build)

**Incompatible / incomplete types against `jose@^6.2.18` and backend `tsconfig`:**

1. **`KeyLike` removed from jose public types.** Installed `jose@6.2.18` exports `KeyInput`, `CryptoKey`, `KeyObject`, `JWK`, etc., but **does not export `KeyLike`**. Code in the new auth crypto module still imports `KeyLike` (jose v4-era name).
2. **Bare `CryptoKey` global unavailable.** `tsconfig.base.json` sets `"lib": ["ES2022"]` (no `DOM`). `dpop.validator.ts` annotates `CryptoKey` without importing it. jose _does_ export a `CryptoKey` type alias — the file simply does not import it.

**Files / packages:**

| Path                                                                    | Issue                                   |
| ----------------------------------------------------------------------- | --------------------------------------- |
| `apps/backend/src/modules/auth/crypto/access-token-key.provider.ts`     | `import type { … KeyLike } from 'jose'` |
| `apps/backend/src/modules/auth/crypto/kms-access-token-key.provider.ts` | same + cast `as KeyLike`                |
| `apps/backend/src/modules/auth/dpop/dpop.validator.ts`                  | untyped-import use of `CryptoKey`       |
| `apps/backend/package.json`                                             | `"jose": "^6.2.18"`                     |
| `tsconfig.base.json` / `apps/backend/tsconfig.json`                     | `lib: ["ES2022"]` — no DOM `CryptoKey`  |

**Evidence (new vs pre-existing):**

- Parent tree at `dbc80b3` had only a stub `apps/backend/src/modules/auth/auth.module.ts` — no crypto providers / DPoP validator with these imports.
- Entire failing surface is part of the auth/KMS work landed in `2a0d09a`.
- Last green CI did not compile these files.

**Not caused by:** missing env vars at build time, Prisma client generation in CI, Next.js config, or incorrect `build:packages` ordering (packages built cleanly).

---

## 6. Local reproduction results

| Command                       | Result                     | Notes                                                                         |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------- |
| `pnpm -v`                     | `9.15.9`                   | Matches CI `pnpm/action-setup` version                                        |
| `node -v`                     | `v26.13.0`                 | CI uses Node 20; TS errors still reproduce                                    |
| `pnpm run format:check`       | **FAIL**                   | 91 local / **68 tracked** (CI-relevant)                                       |
| `pnpm run build:packages`     | **PASS**                   | design-tokens, shared-types, api-contracts, validation-schemas                |
| `pnpm run build:apps`         | **FAIL**                   | Nest: 3 TS errors; Next apps compiled                                         |
| `pnpm run lint` / `typecheck` | Not required for diagnosis | Would be blocked by format in CI; Nest errors already proven via `nest build` |

No dependencies were installed or upgraded for this diagnosis; existing workspace `node_modules` was used.

---

## 7. New vs pre-existing (summary)

| Issue                                                 | Classification                    | Evidence                                                    |
| ----------------------------------------------------- | --------------------------------- | ----------------------------------------------------------- |
| Prettier failures on auth + Phase 2.1 docs + lockfile | **Newly introduced** by `2a0d09a` | Absent from green parent; files/content added in checkpoint |
| Nest `KeyLike` / `CryptoKey` TS errors                | **Newly introduced** by `2a0d09a` | Auth crypto/DPoP files new vs `dbc80b3`                     |
| Flutter job                                           | Unaffected                        | Passed on same run                                          |
| Untracked `packages/database/` Prettier noise         | **Local only**                    | `?? packages/database/` — not in commit                     |

---

## 8. Recommended minimal fixes

Do **not** apply these in this diagnosis pass. Suggested remediation for a follow-up PR:

### A. Formatting (unblocks Lint job)

1. Run Prettier write **only on tracked failing paths**, e.g.:
   ```bash
   pnpm exec prettier --write <list-of-68-tracked-files>
   ```
   or `pnpm run format` if that script maps to the same globs — verify it does not touch untracked `packages/database/`.
2. Optional hardening (separate small change): add `pnpm-lock.yaml` (and later generated Prisma output) to `.prettierignore` so lockfile churn does not fail CI. Not required if lockfile is rewritten once to satisfy Prettier.
3. Re-run `pnpm run format:check` until exit 0 on a clean tree matching `origin/main` + fix commit.

### B. TypeScript / jose (unblocks Build job)

Minimal type-only edits in `@dcmp/backend` (no jose downgrade needed):

1. Replace `KeyLike` with jose v6 types, e.g. `CryptoKey | KeyObject` or `KeyInput` (prefer the narrowest type that matches `privateKey?: …` usage: typically `CryptoKey | Uint8Array` or jose’s `KeyInput`).
2. In `dpop.validator.ts`, either:
   - `import type { CryptoKey } from 'jose'`, or
   - annotate with `Awaited<ReturnType<typeof importJWK>>` / `KeyInput`,
   - avoid adding `"DOM"` to `lib` unless intentionally desired for the whole monorepo.
3. Re-run `pnpm run build:packages && pnpm run build:apps` (and `pnpm run typecheck`).

### C. After A + B

Re-run the previously skipped CI steps locally:

```bash
pnpm run lint
pnpm run typecheck
```

Fix any ESLint findings only if they appear (unknown today).

### Out of scope for minimal fix

- Do not start Phase 2.2.
- Do not change AWS/KMS/IAM.
- Do not commit `packages/database/` unless product-owned.
- Do not relax CI by removing `format:check` or `build:apps`.

---

## 9. Regression tests required

After remediation:

| Check              | Command / suite                                                      | Intent                                                    |
| ------------------ | -------------------------------------------------------------------- | --------------------------------------------------------- |
| Format gate        | `pnpm run format:check`                                              | Must pass with CI globs                                   |
| Backend build      | `pnpm --filter @dcmp/backend run build`                              | Confirms `KeyLike`/`CryptoKey` fixes                      |
| Apps build         | `pnpm run build:apps`                                                | Nest + both Next apps                                     |
| Typecheck          | `pnpm run typecheck`                                                 | Catches residual TS across workspaces                     |
| Lint               | `pnpm run lint`                                                      | First full pass after Prettier unblocks                   |
| Auth unit (no AWS) | `pnpm --filter @dcmp/backend run test:auth:kms-unit` (or equivalent) | Registration, allowlist, multi-key unit specs still green |
| Optional CI re-run | Push fix commit; confirm run green for all three jobs                | End-to-end confirmation                                   |

Live KMS / Redis integration specs are **not** required for CI green (CI does not run them today) but should remain green in the existing local harness before merging if those files were touch-formatted only.

---

## 10. Safe remediation plan (ordered)

1. Format the **68 tracked** Prettier offenders; leave untracked `packages/database/` untouched.
2. Fix jose type imports (`KeyLike` → v6 types; import or replace bare `CryptoKey`).
3. Locally verify: `format:check` → `lint` → `build:packages` → `typecheck` → `build:apps`.
4. Single focused commit on `main` (or short-lived fix branch + PR) — no workflow edits unless ignore-list hardening is intentional.
5. Confirm GitHub Actions run for the fix commit: all three jobs green.

---

## 11. Verdict

| Job                    | Root cause                                                                                              | Introduced by   |
| ---------------------- | ------------------------------------------------------------------------------------------------------- | --------------- |
| Lint & Typecheck       | Prettier `--check` fails on Phase 2.1 auth/docs/lockfile/infra files                                    | `2a0d09a` (new) |
| Build NestJS & Next.js | `nest build` TS2305 (`KeyLike`) + TS2304 (`CryptoKey`) in new auth module vs jose 6 + ES2022-only `lib` | `2a0d09a` (new) |

Both failures are **newly introduced** by the KMS / security-hardening checkpoint. They are **independent**: fixing Prettier alone will not green the build job; fixing types alone will not green the lint job. Flutter remains healthy and should stay out of the fix blast radius.
