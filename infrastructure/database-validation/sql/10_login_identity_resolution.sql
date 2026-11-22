-- Phase 2.1.17 / 10 — Login identity resolution (validation-only)
-- Org-scoped email uniqueness; reject ambiguous multi-org email without org context.
-- Does NOT change the 63-entity architecture; narrow DEFINER helpers only.
\set ON_ERROR_STOP on

GRANT USAGE ON SCHEMA dcmp_security TO dcmp_app;

-- Count active credentialed users for an email (no row payload — anti-enumeration helper).
CREATE OR REPLACE FUNCTION dcmp_security.count_users_for_login(p_email TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  n INTEGER;
BEGIN
  SELECT count(*)::int INTO n
  FROM public.users u
  WHERE lower(u.email) = lower(p_email)
    AND u.deleted_at IS NULL
    AND u.password_hash IS NOT NULL;
  RETURN coalesce(n, 0);
END;
$$;
ALTER FUNCTION dcmp_security.count_users_for_login(TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.count_users_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.count_users_for_login(TEXT) TO dcmp_app;

-- Org-aware login lookup. When p_org IS NULL, returns a row only if exactly one match.
CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_for_login(p_email TEXT, p_org UUID DEFAULT NULL)
RETURNS TABLE (
  id UUID,
  organization_id UUID,
  email TEXT,
  password_hash TEXT,
  display_name TEXT,
  roles TEXT[],
  deleted_at TIMESTAMPTZ,
  match_count INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  n INTEGER;
BEGIN
  SELECT count(*)::int INTO n
  FROM public.users u
  WHERE lower(u.email) = lower(p_email)
    AND u.deleted_at IS NULL
    AND u.password_hash IS NOT NULL
    AND (p_org IS NULL OR u.organization_id = p_org);

  IF p_org IS NULL AND n > 1 THEN
    -- Signal ambiguity without returning a user row.
    RETURN QUERY
    SELECT NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text,
           NULL::text[], NULL::timestamptz, n;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT u.id, u.organization_id, u.email, u.password_hash, u.display_name, u.roles, u.deleted_at, n
  FROM public.users u
  WHERE lower(u.email) = lower(p_email)
    AND u.deleted_at IS NULL
    AND u.password_hash IS NOT NULL
    AND (p_org IS NULL OR u.organization_id = p_org)
  ORDER BY u.created_at ASC
  LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) TO dcmp_app;

-- Keep single-arg overload as thin wrapper for older callers (org-unaware → ambiguous-safe).
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
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
  SELECT r.id, r.organization_id, r.email, r.password_hash, r.display_name, r.roles, r.deleted_at
  FROM dcmp_security.lookup_user_for_login(p_email, NULL::uuid) r
  WHERE r.id IS NOT NULL;
$$;
ALTER FUNCTION dcmp_security.lookup_user_for_login(TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) TO dcmp_app;

\echo NOTICE: 10_login_identity_resolution applied
