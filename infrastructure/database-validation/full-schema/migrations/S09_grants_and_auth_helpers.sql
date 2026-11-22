-- Phase 2.1.18 / S09 — grants + auth DEFINER helpers (from 09/10) + minimal support stubs
\set ON_ERROR_STOP on

-- Tenant DML for dcmp_app
DO $$
DECLARE t TEXT;
BEGIN
  FOR t IN
    SELECT unnest(ARRAY[
      'organization_domains','organization_settings','users','user_sessions','user_session_tokens',
      'refresh_idempotency_records','roles','role_permissions','user_roles','locations','departments',
      'teams','user_organizational_assignments','customer_licenses','license_events','assets',
      'mobile_devices','device_user_sessions','checklist_categories','checklist_templates',
      'checklist_versions','checklist_sections','checklist_questions','question_options',
      'question_conditions','checklist_version_snapshots','checklist_schedules','checklist_assignments',
      'assignment_targets','inspection_instances','inspection_responses','inspection_evidence',
      'approval_records','inspection_history','issues','corrective_actions','corrective_action_history',
      'sync_operations','sync_logs','notifications','notification_preferences','notification_delivery_logs',
      'push_device_tokens','support_tickets','support_ticket_comments','support_diagnostics',
      'support_access_requests','support_access_grants','support_access_logs','audit_logs','generated_files'
    ])
  LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO dcmp_app', t);
  END LOOP;
END $$;

-- dcmp_app may read org and update non-lifecycle profile fields only (ADR-029)
REVOKE ALL ON public.organizations FROM dcmp_app;
GRANT SELECT ON public.organizations TO dcmp_app;
GRANT UPDATE (display_name, timezone, locale, updated_at) ON public.organizations TO dcmp_app;

REVOKE ALL ON public.organizations FROM dcmp_platform_admin;
GRANT SELECT ON public.organizations TO dcmp_platform_admin;
GRANT INSERT ON public.organizations TO dcmp_platform_admin;
GRANT UPDATE (status, suspended_at, suspended_reason, deleted_at, updated_at)
  ON public.organizations TO dcmp_platform_admin;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.platform_admins, public.platform_roles,
  public.platform_permissions, public.platform_admin_role_assignments, public.platform_role_permissions,
  public.permissions, public.license_plans, public.license_plan_entitlements, public.application_releases
  TO dcmp_platform_admin;

GRANT INSERT ON public.security_events TO dcmp_audit_writer;
-- Explicitly no SELECT/UPDATE/DELETE for audit writer
REVOKE SELECT, UPDATE, DELETE ON public.security_events FROM dcmp_audit_writer;

GRANT SELECT ON public.security_events TO dcmp_platform_admin;
GRANT SELECT, INSERT ON public.platform_admin_audit_logs TO dcmp_platform_admin;

GRANT EXECUTE ON FUNCTION public.invalidate_refresh_idempotency(UUID, UUID) TO dcmp_app;

GRANT SELECT, INSERT, UPDATE ON dcmp_security.internal_keys TO dcmp_sec_definer;
GRANT SELECT, INSERT ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;

-- DEFINER SELECT for login/token lookups (NOBYPASSRLS + policies)
GRANT SELECT ON public.users TO dcmp_sec_definer;
GRANT SELECT ON public.user_session_tokens TO dcmp_sec_definer;
DROP POLICY IF EXISTS sec_definer_users_lookup_sel ON public.users;
CREATE POLICY sec_definer_users_lookup_sel ON public.users
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
DROP POLICY IF EXISTS sec_definer_tokens_lookup_sel ON public.user_session_tokens;
CREATE POLICY sec_definer_tokens_lookup_sel ON public.user_session_tokens
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);

CREATE OR REPLACE FUNCTION dcmp_security.count_users_for_login(p_email TEXT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE n INTEGER;
BEGIN
  SELECT count(*)::int INTO n FROM public.users u
  WHERE lower(u.email) = lower(p_email) AND u.deleted_at IS NULL AND u.password_hash IS NOT NULL;
  RETURN coalesce(n, 0);
END;
$$;
ALTER FUNCTION dcmp_security.count_users_for_login(TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.count_users_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.count_users_for_login(TEXT) TO dcmp_app;

CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_for_login(p_email TEXT, p_org UUID DEFAULT NULL)
RETURNS TABLE (
  id UUID, organization_id UUID, email TEXT, password_hash TEXT, display_name TEXT,
  roles TEXT[], deleted_at TIMESTAMPTZ, match_count INTEGER
) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE n INTEGER;
BEGIN
  SELECT count(*)::int INTO n FROM public.users u
  WHERE lower(u.email) = lower(p_email) AND u.deleted_at IS NULL AND u.password_hash IS NOT NULL
    AND (p_org IS NULL OR u.organization_id = p_org);
  IF p_org IS NULL AND n > 1 THEN
    RETURN QUERY SELECT NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text[], NULL::timestamptz, n;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT u.id, u.organization_id, u.email, u.password_hash, u.display_name, u.roles, u.deleted_at, n
  FROM public.users u
  WHERE lower(u.email) = lower(p_email) AND u.deleted_at IS NULL AND u.password_hash IS NOT NULL
    AND (p_org IS NULL OR u.organization_id = p_org)
  ORDER BY u.created_at ASC LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_for_login(TEXT, UUID) TO dcmp_app;

CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_for_login(p_email TEXT)
RETURNS TABLE (
  id UUID, organization_id UUID, email TEXT, password_hash TEXT, display_name TEXT,
  roles TEXT[], deleted_at TIMESTAMPTZ
) LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT r.id, r.organization_id, r.email, r.password_hash, r.display_name, r.roles, r.deleted_at
  FROM dcmp_security.lookup_user_for_login(p_email, NULL::uuid) r WHERE r.id IS NOT NULL;
$$;
ALTER FUNCTION dcmp_security.lookup_user_for_login(TEXT) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_for_login(TEXT) TO dcmp_app;

CREATE OR REPLACE FUNCTION dcmp_security.lookup_token_by_hash(p_hash CHAR(64))
RETURNS TABLE (
  id UUID, organization_id UUID, session_id UUID, token_hash CHAR(64), sequence_number INT,
  expires_at TIMESTAMPTZ, consumed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, replaced_by_token_id UUID
) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN RETURN; END IF;
  RETURN QUERY
  SELECT t.id, t.organization_id, t.session_id, t.token_hash, t.sequence_number,
         t.expires_at, t.consumed_at, t.revoked_at, t.replaced_by_token_id
  FROM public.user_session_tokens t WHERE t.token_hash = p_hash LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_token_by_hash(CHAR) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_token_by_hash(CHAR) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_token_by_hash(CHAR) TO dcmp_app;

CREATE OR REPLACE FUNCTION dcmp_security.lookup_user_by_id(p_org UUID, p_user UUID)
RETURNS TABLE (
  id UUID, organization_id UUID, email TEXT, password_hash TEXT, display_name TEXT,
  roles TEXT[], deleted_at TIMESTAMPTZ
) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.organization_id, u.email, u.password_hash, u.display_name, u.roles, u.deleted_at
  FROM public.users u WHERE u.id = p_user AND u.organization_id = p_org LIMIT 1;
END;
$$;
ALTER FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.lookup_user_by_id(UUID, UUID) TO dcmp_app;

\echo NOTICE: S09_grants_and_auth_helpers OK
