-- Phase 2.1.16 / 09 — Auth gateway persistence (validation-only, narrowly scoped)
-- Adds credential columns + SECURITY DEFINER single lookups for login/token hash.
-- Does NOT apply the full 63-entity schema.
\set ON_ERROR_STOP on

-- Callers need schema USAGE to resolve dcmp_security.* (EXECUTE alone is insufficient).
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_app;

-- SECURITY DEFINER lookups run as dcmp_sec_definer (NOBYPASSRLS). FORCE RLS requires
-- an explicit SELECT policy + table GRANT so single-row login/token resolution works
-- before the app can SET LOCAL app.current_organization_id. dcmp_app never gets these.
GRANT SELECT ON public.users TO dcmp_sec_definer;
GRANT SELECT ON public.user_session_tokens TO dcmp_sec_definer;

DROP POLICY IF EXISTS sec_definer_users_lookup_sel ON public.users;
CREATE POLICY sec_definer_users_lookup_sel ON public.users
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer
  USING (true);

DROP POLICY IF EXISTS sec_definer_tokens_lookup_sel ON public.user_session_tokens;
CREATE POLICY sec_definer_tokens_lookup_sel ON public.user_session_tokens
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer
  USING (true);

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS password_hash TEXT;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS roles TEXT[] NOT NULL DEFAULT ARRAY['inspector']::text[];

COMMENT ON COLUMN public.users.password_hash IS
  'Phase 2.1.16 validation credential hash (scrypt). Not a production IdP store.';

-- Single-row login lookup: email is unique among non-deleted users per org,
-- but login may not yet know org. Returns at most one active user match;
-- if duplicate emails across tenants exist, prefer explicit org filter in app.
CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_for_login(p_email TEXT)
RETURNS TABLE (
  id UUID,
  organization_id UUID,
  email TEXT,
  password_hash TEXT,
  display_name TEXT,
  roles TEXT[],
  deleted_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.organization_id, u.email, u.password_hash, u.display_name, u.roles, u.deleted_at
  FROM public.users u
  WHERE lower(u.email) = lower(p_email)
    AND u.deleted_at IS NULL
    AND u.password_hash IS NOT NULL
  ORDER BY u.created_at ASC
  LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_user_for_login(TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) TO dcmp_app;

-- Global unique token_hash → binding columns (one row). Caller must then SET LOCAL org GUC.
CREATE OR REPLACE FUNCTION dcmp_security.lookup_token_by_hash(p_hash CHAR(64))
RETURNS TABLE (
  id UUID,
  organization_id UUID,
  session_id UUID,
  token_hash CHAR(64),
  sequence_number INT,
  expires_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  replaced_by_token_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT t.id, t.organization_id, t.session_id, t.token_hash, t.sequence_number,
         t.expires_at, t.consumed_at, t.revoked_at, t.replaced_by_token_id
  FROM public.user_session_tokens t
  WHERE t.token_hash = p_hash
  LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_token_by_hash(CHAR) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_token_by_hash(CHAR) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_token_by_hash(CHAR) TO dcmp_app;

CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_by_id(p_org UUID, p_user UUID)
RETURNS TABLE (
  id UUID,
  organization_id UUID,
  email TEXT,
  password_hash TEXT,
  display_name TEXT,
  roles TEXT[],
  deleted_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.organization_id, u.email, u.password_hash, u.display_name, u.roles, u.deleted_at
  FROM public.users u
  WHERE u.id = p_user AND u.organization_id = p_org
  LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) TO dcmp_app;

\echo NOTICE: 09_auth_gateway_persistence applied
