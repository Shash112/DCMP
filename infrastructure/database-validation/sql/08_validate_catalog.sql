-- Phase 2.1.13 / 08 — catalog assertions (run as superuser)
\set ON_ERROR_STOP on

DO $$
DECLARE
  v_owner OID;
  v_ok BOOLEAN;
BEGIN
  -- Role attributes
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname IN ('dcmp_app','dcmp_platform_admin','dcmp_audit_writer','dcmp_sec_definer','dcmp_cleanup')
      AND (rolsuper OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'Runtime/security roles must not be SUPERUSER or BYPASSRLS';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles r ON r.oid = m.roleid
    JOIN pg_roles mbr ON mbr.oid = m.member
    WHERE r.rolname = 'dcmp_sec_definer'
      AND mbr.rolname IN ('dcmp_app','dcmp_platform_admin','dcmp_audit_writer','dcmp_cleanup')
  ) THEN
    RAISE EXCEPTION 'Runtime roles must not be members of dcmp_sec_definer';
  END IF;

  -- Function ownership
  SELECT p.proowner INTO v_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'dcmp_security' AND p.proname = 'verify_support_signature';
  IF v_owner <> (SELECT oid FROM pg_roles WHERE rolname = 'dcmp_sec_definer') THEN
    RAISE EXCEPTION 'verify_support_signature owner mismatch';
  END IF;

  -- FORCE RLS on required tables
  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname IN (
        'organizations','users','user_sessions','user_session_tokens',
        'refresh_idempotency_records','security_events'
      )
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'FORCE RLS missing on required public tables';
  END IF;

  -- Audit writer must NOT have SELECT
  SELECT has_table_privilege('dcmp_audit_writer', 'public.security_events', 'SELECT') INTO v_ok;
  IF v_ok THEN
    RAISE EXCEPTION 'dcmp_audit_writer must not have SELECT on security_events';
  END IF;

  -- App must NOT have full UPDATE on refresh idempotency
  SELECT has_column_privilege('dcmp_app', 'public.refresh_idempotency_records', 'response_ciphertext', 'UPDATE') INTO v_ok;
  IF v_ok THEN
    RAISE EXCEPTION 'dcmp_app must not UPDATE response_ciphertext';
  END IF;

  RAISE NOTICE 'Catalog validation OK';
END $$;
