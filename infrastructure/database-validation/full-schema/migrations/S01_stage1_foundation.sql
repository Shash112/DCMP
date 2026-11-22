-- Phase 2.1.18 / S01 — Stage 1: 20 entities (platform + identity foundation)
\set ON_ERROR_STOP on

CREATE TABLE public.organizations (
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

CREATE TABLE public.organization_domains (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  hostname        TEXT NOT NULL UNIQUE,
  is_primary      BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
ALTER TABLE public.organization_domains OWNER TO dcmp_migrator;

CREATE TABLE public.organization_settings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL UNIQUE REFERENCES public.organizations(id),
  settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
ALTER TABLE public.organization_settings OWNER TO dcmp_migrator;

CREATE TABLE public.platform_admins (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email        TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  is_active    BOOLEAN NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.platform_admins OWNER TO dcmp_migrator;

CREATE TABLE public.platform_roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.platform_roles OWNER TO dcmp_migrator;

CREATE TABLE public.platform_permissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key         TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.platform_permissions OWNER TO dcmp_migrator;

CREATE TABLE public.platform_admin_role_assignments (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id   UUID NOT NULL REFERENCES public.platform_admins(id),
  role_id    UUID NOT NULL REFERENCES public.platform_roles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (admin_id, role_id)
);
ALTER TABLE public.platform_admin_role_assignments OWNER TO dcmp_migrator;

CREATE TABLE public.platform_role_permissions (
  role_id       UUID NOT NULL REFERENCES public.platform_roles(id),
  permission_id UUID NOT NULL REFERENCES public.platform_permissions(id),
  PRIMARY KEY (role_id, permission_id)
);
ALTER TABLE public.platform_role_permissions OWNER TO dcmp_migrator;

CREATE TABLE public.users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  email           TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  password_hash   TEXT,
  roles           TEXT[] NOT NULL DEFAULT ARRAY['inspector']::text[],
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX uq_users_org_email_active
  ON public.users (organization_id, lower(email)) WHERE deleted_at IS NULL;
ALTER TABLE public.users OWNER TO dcmp_migrator;

CREATE TABLE public.user_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  dpop_jkt        TEXT NOT NULL,
  is_active       BOOLEAN NOT NULL DEFAULT true,
  revoked_at      TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.user_sessions OWNER TO dcmp_migrator;

CREATE TABLE public.user_session_tokens (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      UUID NOT NULL,
  session_id           UUID NOT NULL,
  token_hash           CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  sequence_number      INT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at           TIMESTAMPTZ NOT NULL,
  consumed_at          TIMESTAMPTZ,
  revoked_at           TIMESTAMPTZ,
  replaced_by_token_id UUID,
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, session_id, id),
  FOREIGN KEY (organization_id, session_id)
    REFERENCES public.user_sessions (organization_id, id)
);
ALTER TABLE public.user_session_tokens OWNER TO dcmp_migrator;
ALTER TABLE public.user_session_tokens
  ADD CONSTRAINT fk_token_replaced_by
  FOREIGN KEY (organization_id, session_id, replaced_by_token_id)
  REFERENCES public.user_session_tokens (organization_id, session_id, id)
  ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.refresh_idempotency_records (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id       UUID NOT NULL,
  session_id            UUID NOT NULL,
  request_fingerprint   CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  presented_token_hash  CHAR(64) NOT NULL CHECK (presented_token_hash ~ '^[0-9a-f]{64}$'),
  issued_token_id       UUID NOT NULL,
  response_ciphertext   BYTEA NOT NULL,
  response_iv           BYTEA NOT NULL,
  response_auth_tag     BYTEA NOT NULL,
  encryption_key_id     TEXT NOT NULL,
  dpop_jkt              TEXT NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  invalidated_at        TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, session_id, request_fingerprint),
  FOREIGN KEY (organization_id, session_id)
    REFERENCES public.user_sessions (organization_id, id),
  FOREIGN KEY (organization_id, session_id, issued_token_id)
    REFERENCES public.user_session_tokens (organization_id, session_id, id)
);
ALTER TABLE public.refresh_idempotency_records OWNER TO dcmp_migrator;

CREATE OR REPLACE FUNCTION public.trg_refresh_idempotency_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.session_id IS DISTINCT FROM OLD.session_id
       OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
       OR NEW.presented_token_hash IS DISTINCT FROM OLD.presented_token_hash
       OR NEW.issued_token_id IS DISTINCT FROM OLD.issued_token_id
       OR NEW.response_ciphertext IS DISTINCT FROM OLD.response_ciphertext
       OR NEW.response_iv IS DISTINCT FROM OLD.response_iv
       OR NEW.response_auth_tag IS DISTINCT FROM OLD.response_auth_tag
       OR NEW.encryption_key_id IS DISTINCT FROM OLD.encryption_key_id
       OR NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'refresh_idempotency_records immutable except invalidated_at';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER refresh_idempotency_immutable
  BEFORE UPDATE ON public.refresh_idempotency_records
  FOR EACH ROW EXECUTE FUNCTION public.trg_refresh_idempotency_immutable();

CREATE OR REPLACE FUNCTION public.invalidate_refresh_idempotency(p_org UUID, p_session UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  UPDATE public.refresh_idempotency_records
     SET invalidated_at = clock_timestamp()
   WHERE organization_id = p_org AND session_id = p_session AND invalidated_at IS NULL;
END;
$$;
ALTER FUNCTION public.invalidate_refresh_idempotency(UUID, UUID) OWNER TO dcmp_migrator;

CREATE TABLE public.roles (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  name            TEXT NOT NULL,
  description     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, name)
);
ALTER TABLE public.roles OWNER TO dcmp_migrator;

CREATE TABLE public.permissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key         TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.permissions OWNER TO dcmp_migrator;

CREATE TABLE public.role_permissions (
  organization_id UUID NOT NULL,
  role_id         UUID NOT NULL,
  permission_id   UUID NOT NULL REFERENCES public.permissions(id),
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (organization_id, role_id) REFERENCES public.roles (organization_id, id)
);
ALTER TABLE public.role_permissions OWNER TO dcmp_migrator;

CREATE TABLE public.user_roles (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  role_id         UUID NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, user_id, role_id),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id),
  FOREIGN KEY (organization_id, role_id) REFERENCES public.roles (organization_id, id)
);
ALTER TABLE public.user_roles OWNER TO dcmp_migrator;

CREATE TABLE public.locations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  code            TEXT NOT NULL,
  name            TEXT NOT NULL,
  parent_id       UUID,
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, code),
  FOREIGN KEY (organization_id, parent_id) REFERENCES public.locations (organization_id, id)
);
ALTER TABLE public.locations OWNER TO dcmp_migrator;

CREATE TABLE public.departments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  code            TEXT NOT NULL,
  name            TEXT NOT NULL,
  parent_id       UUID,
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, code),
  FOREIGN KEY (organization_id, parent_id) REFERENCES public.departments (organization_id, id)
);
ALTER TABLE public.departments OWNER TO dcmp_migrator;

CREATE TABLE public.teams (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  department_id   UUID NOT NULL,
  code            TEXT NOT NULL,
  name            TEXT NOT NULL,
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, code),
  FOREIGN KEY (organization_id, department_id)
    REFERENCES public.departments (organization_id, id)
);
ALTER TABLE public.teams OWNER TO dcmp_migrator;

CREATE TABLE public.user_organizational_assignments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  location_id     UUID,
  department_id   UUID,
  team_id         UUID,
  is_primary      BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id),
  FOREIGN KEY (organization_id, location_id) REFERENCES public.locations (organization_id, id),
  FOREIGN KEY (organization_id, department_id) REFERENCES public.departments (organization_id, id),
  FOREIGN KEY (organization_id, team_id) REFERENCES public.teams (organization_id, id)
);
ALTER TABLE public.user_organizational_assignments OWNER TO dcmp_migrator;

-- Org lifecycle: platform admin may only update lifecycle columns (ADR-029)
CREATE OR REPLACE FUNCTION public.trg_org_lifecycle_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF current_user = 'dcmp_platform_admin' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_code IS DISTINCT FROM OLD.org_code
       OR NEW.data_region IS DISTINCT FROM OLD.data_region
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.locale IS DISTINCT FROM OLD.locale
       OR NEW.billing_account_id IS DISTINCT FROM OLD.billing_account_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
      RAISE EXCEPTION 'platform admin cannot mutate identity/profile columns on organizations';
    END IF;
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;
CREATE TRIGGER org_lifecycle_guard
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW EXECUTE FUNCTION public.trg_org_lifecycle_guard();

\echo NOTICE: S01_stage1_foundation OK (20 entities)
