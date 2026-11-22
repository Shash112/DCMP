-- Phase 2.1.13 / 04 — security_events + support + dcmp_security tables
\set ON_ERROR_STOP on

CREATE TABLE IF NOT EXISTS public.security_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NULL REFERENCES public.organizations(id),
  event_category  TEXT NOT NULL CHECK (event_category IN (
    'AUTH_FAILURE','TOKEN_REUSE','DPOP_FAILURE','SUPPORT_ACCESS',
    'TAMPER_ATTEMPT','PRIVILEGE_VIOLATION','SESSION_REVOCATION','VALIDATION_TEST'
  )),
  severity        TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  event_source    TEXT NOT NULL CHECK (event_source IN ('GATEWAY','AUTH_SERVICE','DATABASE_TRIGGER','ADMIN_PORTAL')),
  actor_id        UUID,
  correlation_id  UUID,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  recorded_by     TEXT NOT NULL DEFAULT CURRENT_USER,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.security_events OWNER TO dcmp_migrator;

CREATE OR REPLACE FUNCTION public.fn_prevent_audit_dml()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit UPDATE/DELETE prohibited' USING ERRCODE = '42501';
END; $$;

CREATE OR REPLACE FUNCTION public.fn_prevent_audit_truncate()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit TRUNCATE prohibited' USING ERRCODE = '42501';
END; $$;

DROP TRIGGER IF EXISTS trg_protect_security_events_dml ON public.security_events;
CREATE TRIGGER trg_protect_security_events_dml
  BEFORE UPDATE OR DELETE ON public.security_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_prevent_audit_dml();

DROP TRIGGER IF EXISTS trg_protect_security_events_truncate ON public.security_events;
CREATE TRIGGER trg_protect_security_events_truncate
  BEFORE TRUNCATE ON public.security_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_prevent_audit_truncate();

CREATE OR REPLACE FUNCTION public.fn_security_events_before_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.id := COALESCE(NEW.id, gen_random_uuid());
  NEW.created_at := clock_timestamp();
  NEW.recorded_by := CURRENT_USER;
  IF CURRENT_USER = 'dcmp_audit_writer' AND NEW.event_source IS DISTINCT FROM 'GATEWAY' THEN
    RAISE EXCEPTION 'DCMP-SEC-42501: invalid event_source for audit writer' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS trg_security_events_before_insert ON public.security_events;
CREATE TRIGGER trg_security_events_before_insert
  BEFORE INSERT ON public.security_events
  FOR EACH ROW EXECUTE FUNCTION public.fn_security_events_before_insert();

-- Minimal support tables for SECURITY DEFINER paths
CREATE TABLE IF NOT EXISTS public.support_access_requests (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   UUID NOT NULL REFERENCES public.organizations(id),
  platform_admin_id UUID NOT NULL,
  status            TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','DENIED','REVOKED')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.support_access_requests OWNER TO dcmp_migrator;

CREATE TABLE IF NOT EXISTS public.support_access_grants (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id      UUID NOT NULL REFERENCES public.support_access_requests(id),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  status          TEXT NOT NULL DEFAULT 'ACTIVE',
  revoked_at      TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.support_access_grants OWNER TO dcmp_migrator;

CREATE TABLE IF NOT EXISTS dcmp_security.internal_keys (
  key_id      TEXT PRIMARY KEY,
  key_secret  BYTEA NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
  valid_from  TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE dcmp_security.internal_keys OWNER TO dcmp_sec_definer;

CREATE TABLE IF NOT EXISTS dcmp_security.consumed_support_assertions (
  jti         UUID PRIMARY KEY,
  admin_id    UUID NOT NULL,
  grant_id    UUID NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL
);
ALTER TABLE dcmp_security.consumed_support_assertions OWNER TO dcmp_sec_definer;

CREATE TABLE IF NOT EXISTS dcmp_security.support_session_challenges (
  challenge_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  platform_admin_id UUID NOT NULL,
  organization_id   UUID NOT NULL,
  grant_id          UUID NOT NULL REFERENCES public.support_access_grants(id) ON DELETE CASCADE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at        TIMESTAMPTZ NOT NULL,
  consumed_at       TIMESTAMPTZ,
  transaction_xid   BIGINT
);
ALTER TABLE dcmp_security.support_session_challenges OWNER TO dcmp_sec_definer;
