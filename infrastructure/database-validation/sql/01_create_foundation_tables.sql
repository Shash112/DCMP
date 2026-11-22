-- Phase 2.1.13 / 01 — foundation (organizations + minimal platform stubs)
\set ON_ERROR_STOP on

CREATE TABLE IF NOT EXISTS public.organizations (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_code           TEXT NOT NULL UNIQUE,
  display_name       TEXT NOT NULL,
  logo_url           TEXT,
  timezone           TEXT NOT NULL DEFAULT 'UTC',
  locale             TEXT NOT NULL DEFAULT 'en-US',
  status             TEXT NOT NULL DEFAULT 'ACTIVE'
                       CHECK (status IN ('ACTIVE','SUSPENDED','ARCHIVED')),
  suspended_at       TIMESTAMPTZ,
  suspended_reason   TEXT,
  deleted_at         TIMESTAMPTZ,
  billing_account_id UUID,
  data_region        TEXT NOT NULL DEFAULT 'us-east-1',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  created_by         UUID,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE public.organizations OWNER TO dcmp_migrator;
