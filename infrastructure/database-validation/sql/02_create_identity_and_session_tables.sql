-- Phase 2.1.13 / 02 — identity & sessions (Stage 1 subset for security validation)
\set ON_ERROR_STOP on

CREATE TABLE IF NOT EXISTS public.users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  email           TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  deleted_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_org_email_active
  ON public.users (organization_id, lower(email)) WHERE deleted_at IS NULL;
ALTER TABLE public.users OWNER TO dcmp_migrator;

CREATE TABLE IF NOT EXISTS public.user_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  user_id         UUID NOT NULL,
  dpop_jkt        TEXT NOT NULL,
  is_active       BOOLEAN NOT NULL DEFAULT true,
  revoked_at      TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, user_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.user_sessions OWNER TO dcmp_migrator;

CREATE TABLE IF NOT EXISTS public.user_session_tokens (
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

-- Deferrable replacement FK (ADR-014)
ALTER TABLE public.user_session_tokens
  DROP CONSTRAINT IF EXISTS fk_token_replaced_by;
ALTER TABLE public.user_session_tokens
  ADD CONSTRAINT fk_token_replaced_by
  FOREIGN KEY (organization_id, session_id, replaced_by_token_id)
  REFERENCES public.user_session_tokens (organization_id, session_id, id)
  ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
