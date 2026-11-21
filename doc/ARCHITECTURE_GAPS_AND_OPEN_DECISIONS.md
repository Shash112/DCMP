# DCMP — Architecture Gaps, Inconsistencies & Open Decisions

**Product:** Digital Checklist Management Platform (DCMP)  
**Author / Governance:** Senior Software Architect & DevOps Lead  
**Document Status:** Open Architecture Decisions & Risk Register  
**Last Updated:** November 2026 (Phase 1 Baseline)

---

## 1. Purpose

This document formally records all architectural discrepancies, documentation gaps, technical trade-offs, and open engineering decisions identified during Phase 1 inspection of the DCMP documentation baseline.

Per project engineering rules, important architectural decisions and conflicts must not be silently resolved. Each item below requires explicit stakeholder sign-off or architectural consensus prior to production deployment.

---

## 2. Identified Discrepancies and Open Decisions

### GAP-001: Documentation Directory Naming (`docs/` vs `doc/`)

- **Context:** The existing repository structure on disk contains documentation under `DCMP/docs/`. The Phase 1 specification prompt and SRS Section 10 refer interchangeably to `doc/` and `docs/`.
- **Impact:** Potential path confusion for automated CI scripts and developers.
- **Resolution Strategy Adopted in Phase 1:**
  - Preserved the existing 16 specification documents inside `docs/` completely intact (no files renamed, moved, or deleted).
  - Created `doc/` to house the operational governance documentation (`PROJECT_DOCUMENTATION_INDEX.md`, `ARCHITECTURE_GAPS_AND_OPEN_DECISIONS.md`, `REPOSITORY_STRUCTURE.md`, `LOCAL_DEVELOPMENT_SETUP.md`).
  - Documented both paths in the README and build scripts.
- **Decision Status:** Resolved for Phase 1. Recommend keeping `docs/` as the primary folder and aliasing `doc/` in CI.

---

### GAP-002: Tenant Isolation Enforcement — Logical Query Filtering vs PostgreSQL Row-Level Security (RLS)

- **Context:**
  - The Database Design Document (DDD Section 3) specifies a shared database and schema with mandatory `organization_id UUID NOT NULL` on all 47 tenant-owned tables, supported by composite unique constraints `(organization_id, id)` and composite foreign keys.
  - The Security Design Document recommends logical application-level scoping via NestJS repositories and query services, with PostgreSQL RLS cited as a future defense-in-depth option.
- **Trade-off:**
  - _Option A (Logical Isolation):_ NestJS query filters automatically attach `where: { organization_id }` across all Prisma queries. High developer velocity, standard Prisma ORM compatibility, lower connection pool overhead.
  - _Option B (PostgreSQL RLS):_ Enforce `SET LOCAL app.current_organization_id = ...` per transaction with PostgreSQL policies. Strongest database-level protection against developer bug leakage, but introduces connection pooling complexities (PgBouncer transaction pooling requirements) and Prisma extension overhead.
- **Recommendation:** Implement Option A for MVP (with NestJS tenant interception and composite foreign keys), while designing repository interfaces so Option B (RLS) can be enabled seamlessly during hardening without changing application logic.
- **Decision Status:** Open for technical steering committee approval.

---

### GAP-003: Shared Packages Taxonomy — `permissions` Package

- **Context:**
  - SRS Section 10 proposed: `packages/shared-types`, `packages/api-contracts`, `packages/validation-schemas`, `packages/permissions`, `packages/design-tokens`.
  - Phase 1 prompt proposed: `packages/shared-types`, `packages/api-contracts`, `packages/validation-schemas`, `packages/design-tokens`.
- **Resolution Strategy Adopted in Phase 1:**
  - Placed permission enums, role-permission matrices, and scope evaluation interfaces inside `@dcmp/shared-types/permissions` and corresponding validation schemas in `@dcmp/validation-schemas/permissions`.
  - Avoided proliferation of tiny packages during project initialization while keeping permission definitions decoupled from business logic.
- **Decision Status:** Resolved for Phase 1; can be split into a standalone `@dcmp/permissions` package if permission evaluation needs to be embedded in standalone worker microservices in the future.

---

### GAP-004: Mobile Local Persistence Driver — Drift vs sqflite

- **Context:**
  - `DCMP_Mobile_Offline_Sync_Specification_v1.0.docx` specifies a local SQLite database for the Flutter Android client.
  - Two leading Flutter/Dart SQLite libraries are available:
    1. **Drift (formerly Moor):** Type-safe Dart SQLite abstraction with compile-time query verification, automatic migrations, and reactive streams.
    2. **sqflite:** Raw SQLite wrapper with direct SQL execution and lighter compile-time footprint.
- **Recommendation:** Adopt **Drift** (`drift` + `drift_flutter`). The complex relational schema of checklists, sections, questions, conditional branches, assignments, and sync queue benefits significantly from compile-time type safety and migration tooling.
- **Decision Status:** Open for mobile lead confirmation.

---

### GAP-005: Web Authentication Session Strategy

- **Context:**
  - TAD and Security Design specify short-lived access JWTs (15 min) and rotating refresh tokens (7-30 days).
  - Next.js web applications (Customer Web and Platform Admin) can store tokens either:
    1. In-memory (access token) + HTTP-only `SameSite=Lax` cookie (refresh token).
    2. Encrypted session cookie storing both tokens managed by Next.js middleware / Route Handlers.
    3. Web LocalStorage (vulnerable to XSS, discouraged by Security Design).
- **Recommendation:** Implement Option 2 or Option 1 (HTTP-only secure cookies with Next.js BFF proxy to NestJS). This prevents script access to tokens in web browsers and adheres to the strict security rules.
- **Decision Status:** Recommended for implementation in Phase 2.

---

### GAP-006: Local Subdomain Routing in Development

- **Context:**
  - Customer Web uses subdomains (`<tenant>.app.yourproduct.com`) to resolve tenant context.
  - In local development (`localhost`), subdomains such as `acme.localhost:3001` are supported by modern browsers (RFC 6761), but require special handling on some operating systems and development tooling.
- **Recommendation:** Support both:
  1. Subdomain parsing (`<tenant>.localhost:3001` or `lvh.me:3001`).
  2. Fallback header `X-Tenant-Slug: acme` in development and API testing.
- **Decision Status:** Accepted baseline convention for development.

---

### GAP-007: Docker Host Availability in Local Environment

- **Context:**
  - Docker Compose configuration is required for local PostgreSQL 16 and Redis 7.
  - On the current development host environment, Docker CLI / Docker daemon is not installed.
- **Impact:** Live container execution cannot be executed directly on this machine during Phase 1 verification.
- **Mitigation:**
  - Validated `docker-compose.yml` against Docker Compose v2 specification.
  - Provided clear instructions in `doc/LOCAL_DEVELOPMENT_SETUP.md` for launching services once Docker Desktop or an external Docker host is connected.
  - Documented as an active environment limitation.
- **Decision Status:** Recorded as an external environment dependency blocker.

---

### GAP-008: Outbox Pattern & Background Event Processing

- **Context:**
  - TAD Section 3.1 states: "External side effects (email, push, PDF, S3 processing) should be queued or coordinated using an outbox pattern where delivery consistency matters."
  - BullMQ with Redis is specified for queueing.
- **Open Decision:** Determine whether an explicit `outbox_events` table is required in PostgreSQL for transactional event dispatching before BullMQ ingestion, or whether transactional BullMQ producers via Redis suffice for MVP.
- **Decision Status:** To be finalized during Backend Sprint 1.

---

## 3. Summary of Approvals Required

| Decision ID | Summary                                       | Recommended Option                                            | Approver                       |
| ----------- | --------------------------------------------- | ------------------------------------------------------------- | ------------------------------ |
| GAP-002     | PostgreSQL RLS vs Application-Level Isolation | Application-level with composite keys for MVP; RLS in Phase 3 | Tech Lead / Security Architect |
| GAP-004     | Flutter Local SQLite Driver                   | Drift (`drift_flutter`)                                       | Mobile Lead                    |
| GAP-005     | Next.js Web Token Persistence                 | HTTP-only SameSite cookies via Next.js Route Handlers         | Web Lead / Security Architect  |
| GAP-008     | Outbox table vs Direct BullMQ queueing        | Direct BullMQ for MVP; Outbox table for audit-critical events | Backend Lead                   |
