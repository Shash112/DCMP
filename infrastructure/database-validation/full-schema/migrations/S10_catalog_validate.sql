-- Phase 2.1.18 / S10 — catalog validation for 63 entities
\set ON_ERROR_STOP on

DO $$
DECLARE
  expected TEXT[] := ARRAY[
    'organizations','organization_domains','organization_settings','platform_admins','platform_roles',
    'platform_permissions','platform_admin_role_assignments','platform_role_permissions','users',
    'user_sessions','user_session_tokens','refresh_idempotency_records','roles','permissions',
    'role_permissions','user_roles','locations','departments','teams','user_organizational_assignments',
    'license_plans','license_plan_entitlements','customer_licenses','license_events','application_releases',
    'assets','mobile_devices','device_user_sessions','checklist_categories','checklist_templates',
    'checklist_versions','checklist_sections','checklist_questions','question_options','question_conditions',
    'checklist_version_snapshots','checklist_schedules','checklist_assignments','assignment_targets',
    'inspection_instances','inspection_responses','inspection_evidence','approval_records','inspection_history',
    'issues','corrective_actions','corrective_action_history','sync_operations','sync_logs',
    'notifications','notification_preferences','notification_delivery_logs','push_device_tokens',
    'support_tickets','support_ticket_comments','support_diagnostics','support_access_requests',
    'support_access_grants','support_access_logs','audit_logs','platform_admin_audit_logs','security_events',
    'generated_files'
  ];
  missing TEXT[];
  n INT;
BEGIN
  SELECT array_agg(e ORDER BY e) INTO missing
  FROM unnest(expected) e
  WHERE NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = e AND c.relkind = 'r'
  );
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'Missing public tables: %', missing;
  END IF;
  SELECT count(*) INTO n FROM unnest(expected);
  IF n <> 63 THEN
    RAISE EXCEPTION 'Expected array length 63, got %', n;
  END IF;

  -- Role hard checks
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname IN ('dcmp_app','dcmp_platform_admin','dcmp_audit_writer','dcmp_cleanup')
      AND (rolsuper OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'Runtime roles must not be SUPERUSER or BYPASSRLS';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles r ON r.oid = m.roleid
    JOIN pg_roles u ON u.oid = m.member
    WHERE r.rolname = 'dcmp_sec_definer'
      AND u.rolname IN ('dcmp_app','dcmp_platform_admin','dcmp_audit_writer','dcmp_cleanup')
  ) THEN
    RAISE EXCEPTION 'Runtime roles must not be members of dcmp_sec_definer';
  END IF;
END $$;

\echo NOTICE: S10_catalog_validate OK
