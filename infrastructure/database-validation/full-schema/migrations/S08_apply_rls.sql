-- Phase 2.1.18 / S08 — ENABLE/FORCE RLS + dual-tier policies for all applicable tables
\set ON_ERROR_STOP on

-- Tenant-root: organizations
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_org_select_p ON public.organizations;
DROP POLICY IF EXISTS app_org_select_r ON public.organizations;
DROP POLICY IF EXISTS app_org_update_p ON public.organizations;
DROP POLICY IF EXISTS app_org_update_r ON public.organizations;
DROP POLICY IF EXISTS padmin_org_ins ON public.organizations;
DROP POLICY IF EXISTS padmin_org_sel ON public.organizations;
DROP POLICY IF EXISTS padmin_org_upd ON public.organizations;
CREATE POLICY app_org_select_p ON public.organizations AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_org_select_r ON public.organizations AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY app_org_update_p ON public.organizations AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true);
CREATE POLICY app_org_update_r ON public.organizations AS RESTRICTIVE FOR UPDATE TO dcmp_app
  USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY padmin_org_ins ON public.organizations AS PERMISSIVE FOR INSERT TO dcmp_platform_admin WITH CHECK (true);
CREATE POLICY padmin_org_sel ON public.organizations AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);
CREATE POLICY padmin_org_upd ON public.organizations AS PERMISSIVE FOR UPDATE TO dcmp_platform_admin USING (true) WITH CHECK (true);

-- Apply dual-tier tenant-owned policies
DO $$
DECLARE
  t TEXT;
  tables TEXT[] := ARRAY[
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
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS app_%I_p ON public.%I', t, t);
    EXECUTE format('DROP POLICY IF EXISTS app_%I_r ON public.%I', t, t);
    IF t = 'refresh_idempotency_records' THEN
      EXECUTE format('DROP POLICY IF EXISTS app_%I_sel ON public.%I', t, t);
      EXECUTE format('DROP POLICY IF EXISTS app_%I_ins ON public.%I', t, t);
      EXECUTE format('DROP POLICY IF EXISTS app_%I_upd ON public.%I', t, t);
      EXECUTE format(
        'CREATE POLICY app_%I_sel ON public.%I AS PERMISSIVE FOR SELECT TO dcmp_app USING (true)', t, t);
      EXECUTE format(
        'CREATE POLICY app_%I_ins ON public.%I AS PERMISSIVE FOR INSERT TO dcmp_app WITH CHECK (true)', t, t);
      EXECUTE format(
        'CREATE POLICY app_%I_upd ON public.%I AS PERMISSIVE FOR UPDATE TO dcmp_app USING (true) WITH CHECK (true)', t, t);
      EXECUTE format(
        'CREATE POLICY app_%I_r ON public.%I AS RESTRICTIVE FOR ALL TO dcmp_app
           USING (organization_id = NULLIF(current_setting(''app.current_organization_id'', true), '''')::uuid)
           WITH CHECK (organization_id = NULLIF(current_setting(''app.current_organization_id'', true), '''')::uuid)',
        t, t);
    ELSE
      EXECUTE format(
        'CREATE POLICY app_%I_p ON public.%I AS PERMISSIVE FOR ALL TO dcmp_app USING (true) WITH CHECK (true)',
        t, t);
      EXECUTE format(
        'CREATE POLICY app_%I_r ON public.%I AS RESTRICTIVE FOR ALL TO dcmp_app
           USING (organization_id = NULLIF(current_setting(''app.current_organization_id'', true), '''')::uuid)
           WITH CHECK (organization_id = NULLIF(current_setting(''app.current_organization_id'', true), '''')::uuid)',
        t, t);
    END IF;
  END LOOP;
END $$;

-- Cross-cutting: security_events, platform_admin_audit_logs
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_sec_evt_p ON public.security_events;
DROP POLICY IF EXISTS app_sec_evt_r ON public.security_events;
DROP POLICY IF EXISTS audit_sec_ins ON public.security_events;
DROP POLICY IF EXISTS padmin_sec_sel ON public.security_events;
CREATE POLICY app_sec_evt_p ON public.security_events AS PERMISSIVE FOR SELECT TO dcmp_app USING (true);
CREATE POLICY app_sec_evt_r ON public.security_events AS RESTRICTIVE FOR SELECT TO dcmp_app
  USING (organization_id IS NOT NULL AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY audit_sec_ins ON public.security_events AS PERMISSIVE FOR INSERT TO dcmp_audit_writer WITH CHECK (true);
CREATE POLICY padmin_sec_sel ON public.security_events AS PERMISSIVE FOR SELECT TO dcmp_platform_admin USING (true);

ALTER TABLE public.platform_admin_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_admin_audit_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS padmin_audit_all ON public.platform_admin_audit_logs;
CREATE POLICY padmin_audit_all ON public.platform_admin_audit_logs
  AS PERMISSIVE FOR ALL TO dcmp_platform_admin USING (true) WITH CHECK (true);

-- dcmp_security tables FORCE RLS for definer
ALTER TABLE dcmp_security.internal_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.internal_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_keys_all ON dcmp_security.internal_keys;
CREATE POLICY sec_keys_all ON dcmp_security.internal_keys
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

ALTER TABLE dcmp_security.consumed_support_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.consumed_support_assertions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_consumed ON dcmp_security.consumed_support_assertions;
CREATE POLICY sec_consumed ON dcmp_security.consumed_support_assertions
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

ALTER TABLE dcmp_security.support_session_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dcmp_security.support_session_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sec_chal ON dcmp_security.support_session_challenges;
CREATE POLICY sec_chal ON dcmp_security.support_session_challenges
  AS PERMISSIVE FOR ALL TO dcmp_sec_definer USING (true) WITH CHECK (true);

\echo NOTICE: S08_apply_rls OK
