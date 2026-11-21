# Digital Checklist Management Platform (DCMP)

[![CI Pipeline](https://github.com/dcmp/dcmp-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/dcmp/dcmp-platform/actions/workflows/ci.yml)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![pnpm Version](https://img.shields.io/badge/pnpm-%3E%3D9.0.0-orange.svg)](https://pnpm.io/)
[![Flutter Version](https://img.shields.io/badge/flutter-%3E%3D3.38.0-blue.svg)](https://flutter.dev/)

**DCMP** is an enterprise-grade, multi-tenant SaaS platform for digital checklists, inspections, audits, recurring tasks, approvals, and corrective actions. It provides a configurable, industry-independent operational engine serving multiple organizations while enforcing strict logical tenant data isolation.

---

## 1. System Architecture

The platform consists of four primary applications and four shared packages organized in a clean monorepo:

### Applications (`apps/`)

- **`apps/backend`**: Central NestJS modular monolith REST API (`/api/v1`) providing authentication, RBAC, tenant resolution, checklist engines, inspection lifecycles, licensing, and device synchronization.
- **`apps/customer-web`**: Next.js 14 web application for customer organization administrators, managers, and reviewers accessed via tenant subdomains.
- **`apps/platform-admin`**: Next.js 14 web application for SaaS platform owners and internal operations (tenants, licenses, releases, and audited support access).
- **`apps/mobile-app`**: Common Flutter Android application privately distributed to customer inspectors with offline-first execution capabilities.

### Shared Packages (`packages/`)

- **`packages/shared-types`**: TypeScript interfaces, enums, tenant context, and standard API envelopes (`@dcmp/shared-types`).
- **`packages/api-contracts`**: API route constants, HTTP headers, and error codes (`@dcmp/api-contracts`).
- **`packages/validation-schemas`**: Zod runtime validation schemas for requests and domain objects (`@dcmp/validation-schemas`).
- **`packages/design-tokens`**: Brand-neutral design tokens for colors, typography, spacing, and shadows (`@dcmp/design-tokens`).

---

## 2. Technology Stack

| Layer                | Technologies                                                           |
| -------------------- | ---------------------------------------------------------------------- |
| **Backend API**      | NestJS 10, Node.js 20+, TypeScript, Pino, Class-Validator, Swagger     |
| **Web Applications** | Next.js 14 (App Router), React 18, TypeScript                          |
| **Mobile Client**    | Flutter 3.38+, Dart 3.10+, Drift SQLite plan, Secure Storage           |
| **Database & Cache** | PostgreSQL 16, Prisma ORM, Redis 7, BullMQ                             |
| **Infrastructure**   | Docker, Docker Compose, AWS (ECS, RDS, S3, CloudFront), GitHub Actions |
| **Monorepo Tooling** | pnpm workspaces, TypeScript Project References, ESLint, Prettier       |

---

## 3. Quick Start & Local Setup

### 3.1 Prerequisites

- **Node.js** `>= 20.0.0`
- **pnpm** `>= 9.0.0` (`npm install -g pnpm@9`)
- **Docker & Docker Compose** (for PostgreSQL 16 & Redis 7)
- **Flutter SDK** `>= 3.38.0` (for mobile app development)

### 3.2 Environment Setup

```bash
# Copy environment configuration
cp .env.example .env

# Install monorepo dependencies
pnpm install

# Install Flutter dependencies
cd apps/mobile-app && flutter pub get && cd ../..
```

### 3.3 Launch Local Infrastructure

```bash
pnpm docker:up
# Or directly:
docker compose up -d
```

This starts:

- **PostgreSQL 16** on `localhost:5432` (database: `dcmp_dev`, user: `dcmp_user`)
- **Redis 7** on `localhost:6379`

To stop infrastructure:

```bash
pnpm docker:down
```

---

## 4. Running the Applications

### 4.1 Backend API (NestJS)

```bash
pnpm dev:backend
```

- Endpoint: `http://localhost:4000/api/v1`
- Health Check: `http://localhost:4000/api/v1/health`
- Swagger OpenAPI Docs: `http://localhost:4000/api/docs`

### 4.2 Customer Web Application (Next.js)

```bash
pnpm dev:customer-web
```

- URL: `http://localhost:3000`

### 4.3 Platform Admin Portal (Next.js)

```bash
pnpm dev:platform-admin
```

- URL: `http://localhost:3001`

### 4.4 Mobile Application (Flutter)

```bash
pnpm dev:mobile
# Or directly:
cd apps/mobile-app && flutter run
```

---

## 5. Development Scripts

| Command                                 | Description                                                 |
| --------------------------------------- | ----------------------------------------------------------- |
| `pnpm run build`                        | Compiles all shared packages, backend, and web applications |
| `pnpm run typecheck`                    | Runs TypeScript type checking across all packages           |
| `pnpm run lint`                         | Runs ESLint across all packages                             |
| `pnpm run format`                       | Formats codebase using Prettier                             |
| `pnpm run format:check`                 | Verifies code formatting compliance                         |
| `cd apps/mobile-app && flutter analyze` | Runs static analysis on the Flutter mobile app              |
| `cd apps/mobile-app && flutter test`    | Executes Flutter unit and widget smoke tests                |

---

## 6. Architecture & Governance Documentation

All design decisions and architectural specifications are documented under `doc/` and `docs/`:

- [Project Documentation Index](file:///doc/PROJECT_DOCUMENTATION_INDEX.md)
- [Architecture Gaps & Open Decisions](file:///doc/ARCHITECTURE_GAPS_AND_OPEN_DECISIONS.md)
- [Repository Structure Guide](file:///doc/REPOSITORY_STRUCTURE.md)
- [Local Development Setup Guide](file:///doc/LOCAL_DEVELOPMENT_SETUP.md)

---

## 7. Current Project Status

- **Phase 1 (Completed):** Project initialization, monorepo setup, shared package contracts, NestJS modular monolith foundation, Next.js web portals, Flutter mobile baseline, Docker Compose dev environment, and documentation indexing.
- **Phase 2 (Next Step):** Database schema modeling with Prisma, PostgreSQL migrations, and Authentication & Tenant Resolution implementation.
