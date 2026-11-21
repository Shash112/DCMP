# DCMP — Repository Structure & Monorepo Architecture

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Software Architect & DevOps Lead  
**Phase:** Phase 1 Project Initialization Baseline

---

## 1. Monorepo Organization

DCMP is structured as a modern multi-project monorepo powered by **pnpm workspaces** for TypeScript/Node.js applications and shared packages, with a dedicated independent **Flutter** application for the Android mobile client.

```
DCMP/
├── .github/
│   └── workflows/
│       └── ci.yml                     # GitHub Actions CI matrix (Lint, Typecheck, Build, Flutter)
├── apps/
│   ├── backend/                       # Central NestJS modular monolith REST API
│   ├── customer-web/                  # Next.js customer organization workspace portal
│   ├── platform-admin/                # Next.js platform owner administration portal
│   └── mobile-app/                    # Common Flutter Android application
├── packages/
│   ├── shared-types/                  # Core domain models, enums, DTOs, API envelopes
│   ├── api-contracts/                 # API route constants, HTTP headers, error codes
│   ├── validation-schemas/            # Zod runtime validation schemas
│   └── design-tokens/                 # Brand-neutral colors, typography, spacing, shadows
├── infrastructure/
│   ├── docker/                        # Production & staging multi-stage Dockerfiles
│   ├── aws/                           # AWS deployment reference & ECS/RDS architecture
│   └── scripts/                       # Local developer bootstrap scripts (Bash & PowerShell)
├── tests/
│   ├── integration/                   # Cross-module, tenant-isolation & persistence test suites
│   └── e2e/                           # End-to-end multi-persona user journey test suites
├── doc/                               # Operational governance documentation
│   ├── PROJECT_DOCUMENTATION_INDEX.md # Document catalogue and authority mapping
│   ├── ARCHITECTURE_GAPS_AND_OPEN_DECISIONS.md # Formal gap and risk register
│   ├── REPOSITORY_STRUCTURE.md        # Monorepo architecture guide (this document)
│   └── LOCAL_DEVELOPMENT_SETUP.md     # Step-by-step developer environment setup guide
├── docs/                              # Original approved specifications (read-only baseline)
│   ├── DCMP_Software_Requirements_Specification_v1.0.docx
│   ├── DCMP_Technical_Architecture_Document_v1.0.docx
│   ├── DCMP_Complete_Database_Design_v1.0.docx
│   ├── DCMP_Logical_ER_Diagram_v1.0.png
│   ├── DCMP_API_Contracts_and_Specifications_v1.0.docx
│   ├── DCMP_API_OpenAPI_v1.0.yaml
│   ├── DCMP_Security_and_Tenant_Isolation_Design_v1.0.docx
│   ├── DCMP_Mobile_Offline_Sync_Specification_v1.0.docx
│   ├── DCMP_UI_UX_Design_Specification_v1.0.docx
│   ├── DCMP_User_Roles_and_Permissions_Matrix_v1.0.docx
│   ├── DCMP_DevOps_and_Deployment_Guide_v1.0.docx
│   ├── DCMP_Detailed_Test_Plan_and_Test_Cases_v1.0.docx
│   ├── DCMP_Development_Backlog_and_Sprint_Plan_v1.0.docx
│   ├── DCMP_Production_Operations_and_Support_Runbook_v1.0.docx
│   ├── DCMP_User_and_Administrator_Manuals_v1.0.docx
│   └── DCMP_AI_Implementation_Master_Plan_v1.0.docx
├── .env.example                       # Complete environment variable template
├── .gitignore                         # Comprehensive monorepo gitignore
├── .eslintrc.json                     # Root ESLint configuration
├── .prettierrc                        # Standard code formatting rules
├── .prettierignore                    # Prettier ignore targets
├── docker-compose.yml                 # Local dev container configuration (PostgreSQL 16 + Redis 7)
├── package.json                       # Monorepo root scripts & dev dependencies
├── pnpm-workspace.yaml                # pnpm workspace definition
├── tsconfig.base.json                 # Shared base TypeScript compiler options & path aliases
└── README.md                          # Quick start and developer operations manual
```

---

## 2. Component Details

### 2.1 Applications (`apps/`)

#### `apps/backend` (NestJS)

- **Framework:** NestJS 10, Node.js 20+, TypeScript.
- **Port:** `4000` (configurable via `PORT`).
- **Base Path:** `/api/v1`.
- **Role:** Central REST API handling multi-tenant operations, authentication, RBAC, licensing, inspections, evidence metadata, and background job coordination.
- **Key Modules:**
  - `src/config/`: Type-safe configuration loading from environment.
  - `src/common/`: Global exception filters (`GlobalHttpExceptionFilter`), response transformers (`ResponseTransformInterceptor`), correlation middleware (`RequestIdMiddleware`), and tenant interceptors (`TenantMiddleware`).
  - `src/modules/health/`: Diagnostic health endpoint (`/api/v1/health`).
  - `src/modules/*`: Architectural module placeholders for `auth`, `organizations`, `users`, `roles`, `licensing`, `checklists`, `inspections`, `assignments`, `evidence`, `notifications`, `audit`, `platform-admin`.

#### `apps/customer-web` (Next.js)

- **Framework:** Next.js 14 (App Router), React 18, TypeScript.
- **Port:** `3000` (configurable via `PORT`).
- **Role:** Customer organization web portal accessed via subdomain (`<tenant>.app.yourproduct.com` or `localhost:3000` with tenant headers).
- **Features:** Responsive dashboard layout, navigation shell, error boundary (`error.tsx`), 404 handler (`not-found.tsx`), and typed API client foundation.

#### `apps/platform-admin` (Next.js)

- **Framework:** Next.js 14 (App Router), React 18, TypeScript.
- **Port:** `3001` (configurable via `PORT`).
- **Role:** Dedicated SaaS owner administration portal for tenant onboarding, licensing, device management, release tracking, and audited support access.
- **Security Boundary:** Completely separate deployable application with dedicated layout, dark administrative visual styling, and restricted access controls.

#### `apps/mobile-app` (Flutter)

- **Framework:** Flutter 3.38+ / Dart 3.10+.
- **Role:** Single common Android mobile application privately distributed to customer employees and inspectors.
- **Architecture:** Offline-first inspection client with Drift SQLite integration plan, Android Keystore secure storage plan, custom design system theme matching web design tokens, and HTTP API client foundation.

---

### 2.2 Shared Packages (`packages/`)

To avoid circular dependencies and maintain clean encapsulation, shared packages follow a strict hierarchy:

```
@dcmp/design-tokens (pure tokens)
@dcmp/shared-types (pure types)
        │
        ├──► @dcmp/api-contracts (depends on shared-types)
        └──► @dcmp/validation-schemas (depends on shared-types + zod)
```

1. **`@dcmp/shared-types`**: Pure TypeScript domain interfaces, enums, tenant context models, and standard API response envelope definitions.
2. **`@dcmp/api-contracts`**: API route mapping constants (aligned with OpenAPI 3.0.3), custom header definitions (`x-request-id`, `x-tenant-slug`, etc.), and standard error code constants.
3. **`@dcmp/validation-schemas`**: Zod runtime validation schemas for requests and domain inputs, ensuring runtime type safety across backend and web applications.
4. **`@dcmp/design-tokens`**: Brand-neutral design system variables for colors (primary indigo, neutrals, semantic success/warning/danger), typography, spacing (4px scale), and shadow elevations.

---

### 2.3 Infrastructure (`infrastructure/` & `docker-compose.yml`)

- **`docker-compose.yml`**: Configures PostgreSQL 16 (port 5432) and Redis 7 (port 6379) with health checks, persistent volumes, and isolated bridge network.
- **`infrastructure/docker/`**: Multi-stage production-ready Dockerfiles for `backend`, `customer-web`, and `platform-admin`.
- **`infrastructure/aws/`**: Reference architecture for ECS Fargate, RDS PostgreSQL, ElastiCache Redis, S3, and CloudFront.
- **`infrastructure/scripts/`**: One-command developer bootstrap scripts (`dev-setup.sh` for Unix/macOS, `dev-setup.ps1` for Windows PowerShell).
