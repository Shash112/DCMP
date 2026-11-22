-- Phase 2.1.13 / 05 — ENABLE/FORCE RLS + permissive/restrictive policies
\set ON_ERROR_STOP on

-- organizations
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS app_org_select_permissive ON public.organizations;
DROP POLICY IF EXISTS app_org_select_restrictive ON public.organizations;
DROP POLICY IF EXISTS app_org_update_permissive ON public.organizations;
DROP POLICY IF EXISTS app_org_update_restrictive ON public.organizations;
DROP POLICY IF EXISTS platform_admin_org_insert_permissive ON public.organizations;
DROP POLICY IF EXISTS platform_admin_org_select_permissive ON public.organizations;
DROP POLICY IF EXISTS platform_admin_org_update_permissive ON public.organizations;

CREATE POLICY app_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_org_select_restrictive ON public.organizations
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY app_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_org_update_restrictive ON public.organizations
  AS RESTRICTIVE FOR UPDATE TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY platform_admin_org_insert_permissive ON public.organizations
  AS PERMISSIVE FOR INSERT TO dcmp_platform_admin WITH CHECK (true);
CREATE POLICY platform_admin_org_select_permissive ON public.organizations
  AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);
CREATE POLICY platform_admin_org_update_permissive ON public.organizations
  AS PERMISSIVE FOR UPDATE TO dcmp_platform_admin USING (true) WITH CHECK (true);

-- helper: tenant owned dual-tier for a table
-- Applied inline for users, sessions, tokens, refresh_idempotency

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_users_p ON public.users;
DROP POLICY IF EXISTS app_users_r ON public.users;
CREATE POLICY app_users_p ON public.users AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_users_r ON public.users AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
-- platform-admin support policies attached in 07 after verify_support_signature exists

ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_sessions_p ON public.user_sessions;
DROP POLICY IF EXISTS app_sessions_r ON public.user_sessions;
CREATE POLICY app_sessions_p ON public.user_sessions AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_sessions_r ON public.user_sessions AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

ALTER TABLE public.user_session_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_session_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_tokens_p ON public.user_session_tokens;
DROP POLICY IF EXISTS app_tokens_r ON public.user_session_tokens;
CREATE POLICY app_tokens_p ON public.user_session_tokens AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_tokens_r ON public.user_session_tokens AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

ALTER TABLE public.refresh_idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_idempotency_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_idempo_sel_p ON public.refresh_idempotency_records;
DROP POLICY IF EXISTS app_idempo_ins_p ON public.refresh_idempotency_records;
DROP POLICY IF EXISTS app_idempo_upd_p ON public.refresh_idempotency_records;
DROP POLICY IF EXISTS app_idempo_r ON public.refresh_idempotency_records;
DROP POLICY IF EXISTS cleanup_idempo_del_p ON public.refresh_idempotency_records;
DROP POLICY IF EXISTS cleanup_idempo_r ON public.refresh_idempotency_records;
CREATE POLICY app_idempo_sel_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_idempo_ins_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR INSERT TO dcmp_app WITH CHECK (true);
CREATE POLICY app_idempo_upd_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_idempo_r ON public.refresh_idempotency_records
  AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY cleanup_idempo_del_p ON public.refresh_idempotency_records
  AS PERMISSIVE FOR DELETE TO dcmp_cleanup USING (true);
CREATE POLICY cleanup_idempo_r ON public.refresh_idempotency_records
  AS RESTRICTIVE FOR DELETE TO dcmp_cleanup
  USING (expires_at < clock_timestamp() OR invalidated_at IS NOT NULL);

ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_writer_insert_permissive ON public.security_events;
DROP POLICY IF EXISTS app_audit_select_permissive ON public.security_events;
DROP POLICY IF EXISTS app_audit_select_restrictive ON public.security_events;
DROP POLICY IF EXISTS platform_admin_audit_select_permissive ON public.security_events;
CREATE POLICY audit_writer_insert_permissive ON public.security_events
  AS PERMISSIVE FOR INSERT TO dcmp_audit_writer
  WITH CHECK (recorded_by = CURRENT_USER AND event_source = 'GATEWAY');
CREATE POLICY app_audit_select_permissive ON public.security_events
  AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_audit_select_restrictive ON public.security_events
  AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (organization_id IS NOT NULL
    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY platform_admin_audit_select_permissive ON public.security_events
  AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);

-- SECURITY DEFINER dependency RLS
ALTER TABLE dcmp_security.internal_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.internal_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_definer_internal_keys_all ON dcmp_security.internal_keys;
CREATE POLICY sec_definer_internal_keys_all ON dcmp_security.internal_keys
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

ALTER TABLE dcmp_security.consumed_support_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.consumed_support_assertions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_definer_consumed_sel ON dcmp_security.consumed_support_assertions;
DROP POLICY IF EXISTS sec_definer_consumed_ins ON dcmp_security.consumed_support_assertions;
CREATE POLICY sec_definer_consumed_sel ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
CREATE POLICY sec_definer_consumed_ins ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR INSERT TO dcmp_sec_definer WITH CHECK (true);

ALTER TABLE dcmp_security.support_session_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.support_session_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_definer_challenges_all ON dcmp_security.support_session_challenges;
CREATE POLICY sec_definer_challenges_all ON dcmp_security.support_session_challenges
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

ALTER TABLE public.support_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_access_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_definer_grants_select ON public.support_access_grants;
DROP POLICY IF EXISTS app_grants_p ON public.support_access_grants;
DROP POLICY IF EXISTS app_grants_r ON public.support_access_grants;
CREATE POLICY sec_definer_grants_select ON public.support_access_grants
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
CREATE POLICY app_grants_p ON public.support_access_grants AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_grants_r ON public.support_access_grants AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

ALTER TABLE public.support_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_access_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_definer_requests_select ON public.support_access_requests;
DROP POLICY IF EXISTS app_req_p ON public.support_access_requests;
DROP POLICY IF EXISTS app_req_r ON public.support_access_requests;
CREATE POLICY sec_definer_requests_select ON public.support_access_requests
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);
CREATE POLICY app_req_p ON public.support_access_requests AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_req_r ON public.support_access_requests AS RESTRICTIVE FOR ALL TO dcmp_app
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
