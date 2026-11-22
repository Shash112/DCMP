-- Phase 2.1.18 / S02 — Stage 2: licensing, releases, assets, devices (8 entities)
\set ON_ERROR_STOP on

CREATE TABLE public.license_plans (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  is_active   BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.license_plans OWNER TO dcmp_migrator;

CREATE TABLE public.license_plan_entitlements (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id     UUID NOT NULL REFERENCES public.license_plans(id),
  feature_key TEXT NOT NULL,
  limit_value INT,
  UNIQUE (plan_id, feature_key)
);
ALTER TABLE public.license_plan_entitlements OWNER TO dcmp_migrator;

CREATE TABLE public.customer_licenses (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  UUID NOT NULL REFERENCES public.organizations(id),
  plan_id          UUID NOT NULL REFERENCES public.license_plans(id),
  license_key_hash TEXT NOT NULL UNIQUE,
  status           TEXT NOT NULL DEFAULT 'ACTIVE'
                     CHECK (status IN ('ACTIVE','SUSPENDED','EXPIRED','REVOKED')),
  starts_at        TIMESTAMPTZ NOT NULL,
  ends_at          TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
ALTER TABLE public.customer_licenses OWNER TO dcmp_migrator;

CREATE TABLE public.license_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  license_id      UUID NOT NULL,
  event_type      TEXT NOT NULL,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, license_id)
    REFERENCES public.customer_licenses (organization_id, id)
);
ALTER TABLE public.license_events OWNER TO dcmp_migrator;

CREATE TABLE public.application_releases (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  platform     TEXT NOT NULL CHECK (platform IN ('ANDROID','IOS','WEB')),
  version_code TEXT NOT NULL,
  version_name TEXT NOT NULL,
  is_mandatory BOOLEAN NOT NULL DEFAULT false,
  released_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (platform, version_code)
);
ALTER TABLE public.application_releases OWNER TO dcmp_migrator;

CREATE TABLE public.assets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  location_id     UUID,
  asset_tag       TEXT NOT NULL,
  name            TEXT NOT NULL,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, asset_tag),
  FOREIGN KEY (organization_id, location_id)
    REFERENCES public.locations (organization_id, id)
);
ALTER TABLE public.assets OWNER TO dcmp_migrator;

CREATE TABLE public.mobile_devices (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id        UUID NOT NULL REFERENCES public.organizations(id),
  installation_id_hash   TEXT NOT NULL UNIQUE,
  platform               TEXT NOT NULL CHECK (platform IN ('ANDROID','IOS')),
  app_version            TEXT,
  last_seen_at           TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
ALTER TABLE public.mobile_devices OWNER TO dcmp_migrator;

CREATE TABLE public.device_user_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  device_id       UUID NOT NULL,
  user_id         UUID NOT NULL,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  ended_at        TIMESTAMPTZ,
  FOREIGN KEY (organization_id, device_id)
    REFERENCES public.mobile_devices (organization_id, id),
  FOREIGN KEY (organization_id, user_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.device_user_sessions OWNER TO dcmp_migrator;

\echo NOTICE: S02_stage2 OK (8 entities)
