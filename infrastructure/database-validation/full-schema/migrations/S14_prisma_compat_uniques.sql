-- Phase 2.1.19 / S14 — composite uniques required for Prisma composite 1:1 relations
\set ON_ERROR_STOP on

ALTER TABLE public.checklist_version_snapshots
  DROP CONSTRAINT IF EXISTS checklist_version_snapshots_org_version_key;
ALTER TABLE public.checklist_version_snapshots
  ADD CONSTRAINT checklist_version_snapshots_org_version_key
  UNIQUE (organization_id, checklist_version_id);

ALTER TABLE public.support_access_grants
  DROP CONSTRAINT IF EXISTS support_access_grants_org_request_key;
ALTER TABLE public.support_access_grants
  ADD CONSTRAINT support_access_grants_org_request_key
  UNIQUE (organization_id, support_access_request_id);

\echo NOTICE: S14_prisma_compat_uniques OK
