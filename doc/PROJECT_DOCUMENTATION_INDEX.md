# DCMP — Project Documentation Index

**Product:** Digital Checklist Management Platform (DCMP)  
**Author / Governance:** Senior Software Architect & Technical Lead  
**Last Updated:** November 2026 (Phase 1 Baseline)  
**Status:** Approved Documentation Baseline

---

## 1. Executive Summary

This index catalogues all architectural, functional, security, operational, and development documentation governing the Digital Checklist Management Platform (DCMP). These documents serve as the project's single source of truth (SSOT). All development tasks, agent prompts, and architecture decisions must comply with the specifications indexed below.

The source files reside in the project repository root under `docs/` and are cross-referenced across the `doc/` operational indices.

---

## 2. Master Document Inventory

| #   | Document File Name                                         | Formal Title                              | Version | Scope / Governed Areas of Development                                                                                                                                                                     |
| --- | ---------------------------------------------------------- | ----------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `DCMP_Software_Requirements_Specification_v1.0.docx`       | Software Requirements Specification (SRS) | 1.0     | Product vision, functional requirements (FR-001 to FR-030), non-functional requirements (NFRs), tenant boundaries, user personas, MVP boundary, acceptance criteria.                                      |
| 2   | `DCMP_Technical_Architecture_Document_v1.0.docx`           | Technical Architecture Document (TAD)     | 1.0     | Logical modular monolith architecture, shared SaaS infrastructure, tech stack selection, module responsibilities, boundary rules, integration patterns, caching, queueing, observability.                 |
| 3   | `DCMP_Complete_Database_Design_v1.0.docx`                  | Complete Database Design Document (DDD)   | 1.0     | Relational database schema (61 tables across 14 domain groups), naming conventions, UUID primary keys, composite tenant keys, constraints, indexes, JSONB usage, Prisma ORM standards.                    |
| 4   | `DCMP_Logical_ER_Diagram_v1.0.png`                         | Logical Entity-Relationship Diagram       | 1.0     | Visual domain relationship overview connecting organizations, users, licenses, templates, assignments, inspections, issues, evidence, and support tickets.                                                |
| 5   | `DCMP_API_Contracts_and_Specifications_v1.0.docx`          | API Contracts & Specifications            | 1.0.0   | REST API design principles, `/api/v1` base path, standard response envelopes (`success: true/false`), pagination contracts, error catalogue, rate limiting, idempotency keys, JWT handling.               |
| 6   | `DCMP_API_OpenAPI_v1.0.yaml`                               | DCMP OpenAPI 3.0.3 Specification          | 1.0.0   | Machine-readable API schema defining 52 REST endpoints across authentication, organizations, checklists, inspections, evidence, sync, licensing, and administration.                                      |
| 7   | `DCMP_Security_and_Tenant_Isolation_Design_v1.0.docx`      | Security & Tenant-Isolation Design        | 1.0.0   | Threat modeling, tenant isolation enforcement, JWT access + rotating refresh tokens, RBAC authorization, customer support temporary access protocol, S3 presigned URL security, audit trails.             |
| 8   | `DCMP_Mobile_Offline_Sync_Specification_v1.0.docx`         | Mobile Offline Sync Specification         | 1.0     | Flutter Android client architecture, local SQLite schema mirroring, offline inspection execution, bidirectional sync protocol, idempotency, retry mechanisms, conflict resolution.                        |
| 9   | `DCMP_UI_UX_Design_Specification_v1.0.docx`                | UI/UX Design Specification                | 1.0.0   | Visual design language, design tokens (colors, typography, spacing, shadows), responsive web layouts, mobile inspection workflows, form usability, accessibility standards (WCAG 2.1 AA).                 |
| 10  | `DCMP_User_Roles_and_Permissions_Matrix_v1.0.docx`         | User Roles & Permissions Matrix           | 1.0     | Platform roles (Super Admin, Ops Admin, Support), Customer roles (Customer Owner, Admin, Manager, Supervisor, Inspector, Auditor), granular permission keys, scoping rules.                               |
| 11  | `DCMP_DevOps_and_Deployment_Guide_v1.0.docx`               | DevOps & Deployment Guide                 | 1.0     | AWS deployment reference (ECS Fargate/EKS, RDS PostgreSQL, ElastiCache Redis, S3, CloudFront), Docker containerization, GitHub Actions CI/CD pipelines, environment variable strategy, disaster recovery. |
| 12  | `DCMP_Detailed_Test_Plan_and_Test_Cases_v1.0.docx`         | Detailed Test Plan & Test Cases           | 1.0.0   | QA strategy, unit testing, integration testing, cross-tenant isolation attack test scenarios, mobile offline edge cases, performance benchmarks, release acceptance gates.                                |
| 13  | `DCMP_Development_Backlog_and_Sprint_Plan_v1.0.docx`       | Development Backlog & Sprint Plan         | 1.0     | 12 two-week sprint delivery roadmap (Sprints 0 to 11), work breakdown structure (WBS), story point assumptions, dependency chains, MVP feature milestones.                                                |
| 14  | `DCMP_Production_Operations_and_Support_Runbook_v1.0.docx` | Production Operations & Support Runbook   | 1.0     | Operational runbooks, incident response tiers (P1 to P4), health check monitoring, request correlation ID tracing, backup verification, support access grant workflow.                                    |
| 15  | `DCMP_User_and_Administrator_Manuals_v1.0.docx`            | User & Administrator Manuals              | 1.0     | Operating guides: Part I (End User / Inspector), Part II (Customer Administrator), Part III (Platform Super Admin).                                                                                       |
| 16  | `DCMP_AI_Implementation_Master_Plan_v1.0.docx`             | AI Implementation Master Plan             | 1.0.0   | Instructions for AI coding agents and human developers, build sequence, verification rules, guardrails, definition of done, anti-regression protocols.                                                    |

---

## 3. Governance by System Component

### 3.1 Central NestJS Backend (`apps/backend`)

- **Primary Specifications:** TAD, DDD, API Contracts, OpenAPI Specification, Security Design.
- **Rules:**
  - Base path: `/api/v1`.
  - Modular monolith: each domain (auth, organizations, checklists, inspections, etc.) isolated in its own module.
  - Multi-tenant query isolation: all tenant queries scoped by `organization_id` derived from session context.
  - Consistent error envelope (`success: false`, `error: { code, message, details, requestId }`).
  - Request correlation tracking via `X-Request-Id` header and Pino logging.

### 3.2 Customer Web Application (`apps/customer-web`)

- **Primary Specifications:** SRS, UI/UX Design Specification, Roles & Permissions Matrix, API Contracts.
- **Rules:**
  - Subdomain resolution (`<tenant>.app.domain.com`) or header-based tenant resolution in development.
  - Responsive layout for desktop and tablet operations.
  - Strict UI permission gating matching backend RBAC.

### 3.3 Platform Owner Dashboard (`apps/platform-admin`)

- **Primary Specifications:** SRS, Technical Architecture, Roles & Permissions Matrix, Security Design.
- **Rules:**
  - Separate deployable Next.js app to preserve security and administrative boundaries.
  - Governed by Platform Super Admin and Operations Admin roles.
  - No automatic access to customer inspection business data; temporary access requires an approved customer grant.

### 3.4 Common Mobile Application (`apps/mobile-app`)

- **Primary Specifications:** SRS, Mobile Offline Sync Specification, UI/UX Design Specification.
- **Rules:**
  - Single common Flutter Android APK (no customer-specific APK builds).
  - Centralized license activation and tenant branding download.
  - Offline-first execution: local SQLite persistence, private evidence staging, reliable sync queue.

### 3.5 Shared Packages (`packages/*`)

- **Primary Specifications:** TAD, API Contracts, OpenAPI Specification, UI/UX Design Specification.
- **Packages:**
  - `@dcmp/shared-types`: Common TypeScript interfaces, enums, DTOs, and tenant context.
  - `@dcmp/api-contracts`: API route constants, HTTP method definitions, and response envelopes.
  - `@dcmp/validation-schemas`: Zod runtime schemas matching OpenAPI specifications.
  - `@dcmp/design-tokens`: Shared color tokens, spacing, typography, and styling variables.

---

## 4. Maintenance and Change Control

1. Any changes or updates to existing architecture documentation must follow a formal Change Request (CR) process.
2. Architecture deviations and unresolved items must be logged in `doc/ARCHITECTURE_GAPS_AND_OPEN_DECISIONS.md`.
3. Code must never silently override documented specifications.
