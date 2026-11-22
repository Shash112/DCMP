-- Phase 2.1.18 / S07 — Stage 7: notifications, support, audit, files (14 entities) + security schema tables
\set ON_ERROR_STOP on

CREATE TABLE public.notifications (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  user_id         UUID NOT NULL,
  channel         TEXT NOT NULL CHECK (channel IN ('PUSH','EMAIL','IN_APP')),
  title           TEXT NOT NULL,
  body            TEXT,
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  read_at         TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.notifications OWNER TO dcmp_migrator;

CREATE TABLE public.notification_preferences (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  channel         TEXT NOT NULL CHECK (channel IN ('PUSH','EMAIL','IN_APP')),
  enabled         BOOLEAN NOT NULL DEFAULT true,
  UNIQUE (user_id, channel),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.notification_preferences OWNER TO dcmp_migrator;

CREATE TABLE public.notification_delivery_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  notification_id UUID NOT NULL,
  status          TEXT NOT NULL,
  provider_ref    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, notification_id)
    REFERENCES public.notifications (organization_id, id) ON DELETE CASCADE
);
ALTER TABLE public.notification_delivery_logs OWNER TO dcmp_migrator;

CREATE TABLE public.push_device_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  device_id       UUID,
  token           TEXT NOT NULL UNIQUE,
  platform        TEXT NOT NULL CHECK (platform IN ('ANDROID','IOS','WEB')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id),
  FOREIGN KEY (organization_id, device_id) REFERENCES public.mobile_devices (organization_id, id)
);
ALTER TABLE public.push_device_tokens OWNER TO dcmp_migrator;

CREATE TABLE public.support_tickets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  opened_by       UUID NOT NULL,
  assignee_admin  UUID REFERENCES public.platform_admins(id),
  ticket_number   TEXT NOT NULL UNIQUE,
  subject         TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'OPEN',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, opened_by) REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.support_tickets OWNER TO dcmp_migrator;

CREATE TABLE public.support_ticket_comments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  ticket_id       UUID NOT NULL,
  body            TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, ticket_id)
    REFERENCES public.support_tickets (organization_id, id) ON DELETE CASCADE
);
ALTER TABLE public.support_ticket_comments OWNER TO dcmp_migrator;

CREATE TABLE public.support_diagnostics (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  ticket_id       UUID NOT NULL,
  device_id       UUID,
  payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, ticket_id)
    REFERENCES public.support_tickets (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_id)
    REFERENCES public.mobile_devices (organization_id, id)
);
ALTER TABLE public.support_diagnostics OWNER TO dcmp_migrator;

CREATE TABLE public.support_access_requests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  ticket_id       UUID NOT NULL,
  admin_id        UUID NOT NULL REFERENCES public.platform_admins(id),
  status          TEXT NOT NULL DEFAULT 'PENDING',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, ticket_id)
    REFERENCES public.support_tickets (organization_id, id)
);
ALTER TABLE public.support_access_requests OWNER TO dcmp_migrator;

CREATE TABLE public.support_access_grants (
  id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id            UUID NOT NULL,
  support_access_request_id  UUID NOT NULL UNIQUE,
  approved_by_user_id        UUID NOT NULL,
  expires_at                 TIMESTAMPTZ NOT NULL,
  revoked_at                 TIMESTAMPTZ,
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, support_access_request_id)
    REFERENCES public.support_access_requests (organization_id, id),
  FOREIGN KEY (organization_id, approved_by_user_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.support_access_grants OWNER TO dcmp_migrator;

CREATE TABLE public.support_access_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  grant_id        UUID NOT NULL,
  action          TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, grant_id)
    REFERENCES public.support_access_grants (organization_id, id)
);
ALTER TABLE public.support_access_logs OWNER TO dcmp_migrator;

CREATE TABLE public.audit_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  actor_user_id   UUID,
  action          TEXT NOT NULL,
  resource_type   TEXT,
  resource_id     UUID,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, actor_user_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.audit_logs OWNER TO dcmp_migrator;

CREATE TABLE public.platform_admin_audit_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES public.organizations(id),
  admin_id        UUID NOT NULL REFERENCES public.platform_admins(id),
  action          TEXT NOT NULL,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.platform_admin_audit_logs OWNER TO dcmp_migrator;

CREATE TABLE public.security_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES public.organizations(id),
  category        TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.security_events OWNER TO dcmp_migrator;

CREATE TABLE public.generated_files (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  created_by      UUID,
  storage_bucket  TEXT NOT NULL,
  object_key      TEXT NOT NULL,
  file_type       TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (storage_bucket, object_key),
  FOREIGN KEY (organization_id, created_by)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.generated_files OWNER TO dcmp_migrator;

-- Security schema support tables (not counted in 63)
CREATE TABLE dcmp_security.internal_keys (
  key_id     TEXT PRIMARY KEY,
  key_material BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE dcmp_security.internal_keys OWNER TO dcmp_sec_definer;

CREATE TABLE dcmp_security.consumed_support_assertions (
  jti        TEXT PRIMARY KEY,
  admin_id   UUID NOT NULL,
  grant_id   UUID NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE dcmp_security.consumed_support_assertions OWNER TO dcmp_sec_definer;

CREATE TABLE dcmp_security.support_session_challenges (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id   UUID NOT NULL,
  grant_id   UUID NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);
ALTER TABLE dcmp_security.support_session_challenges OWNER TO dcmp_sec_definer;

\echo NOTICE: S07_stage7 OK (14 public entities + security schema)
