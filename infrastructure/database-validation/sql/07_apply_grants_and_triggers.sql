-- Phase 2.1.13 / 07 — grants, org lifecycle trigger, post-function RLS
\set ON_ERROR_STOP on

-- Organization column-level grants (Correction C / ADR-029)
REVOKE ALL ON public.organizations FROM PUBLIC;
REVOKE ALL ON public.organizations FROM dcmp_app, dcmp_platform_admin;
GRANT SELECT ON public.organizations TO dcmp_app;
GRANT UPDATE (display_name, logo_url, timezone, locale, updated_at) ON public.organizations TO dcmp_app;
GRANT SELECT, INSERT ON public.organizations TO dcmp_platform_admin;
GRANT UPDATE (status, suspended_at, suspended_reason, deleted_at, updated_at) ON public.organizations TO dcmp_platform_admin;

CREATE OR REPLACE FUNCTION public.fn_organizations_lifecycle_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF CURRENT_USER = 'dcmp_app' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_code IS DISTINCT FROM OLD.org_code
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR NEW.suspended_at IS DISTINCT FROM OLD.suspended_at
       OR NEW.suspended_reason IS DISTINCT FROM OLD.suspended_reason
       OR NEW.billing_account_id IS DISTINCT FROM OLD.billing_account_id
       OR NEW.data_region IS DISTINCT FROM OLD.data_region
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: tenant cannot modify lifecycle/identity columns' USING ERRCODE = '42501';
    END IF;
  ELSIF CURRENT_USER = 'dcmp_platform_admin' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_code IS DISTINCT FROM OLD.org_code
       OR NEW.billing_account_id IS DISTINCT FROM OLD.billing_account_id
       OR NEW.data_region IS DISTINCT FROM OLD.data_region
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.display_name IS DISTINCT FROM OLD.display_name
       OR NEW.logo_url IS DISTINCT FROM OLD.logo_url
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.locale IS DISTINCT FROM OLD.locale THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: platform admin limited to lifecycle columns' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS trg_organizations_lifecycle_guard ON public.organizations;
CREATE TRIGGER trg_organizations_lifecycle_guard
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW EXECUTE FUNCTION public.fn_organizations_lifecycle_guard();

-- Tenant tables table-level grants
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO dcmp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_sessions TO dcmp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_session_tokens TO dcmp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.support_access_requests TO dcmp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.support_access_grants TO dcmp_app;

-- Correction A: least privilege on refresh_idempotency_records
REVOKE ALL ON public.refresh_idempotency_records FROM PUBLIC;
REVOKE ALL ON public.refresh_idempotency_records FROM dcmp_app, dcmp_cleanup;
GRANT SELECT, INSERT ON public.refresh_idempotency_records TO dcmp_app;
-- Only invalidated_at may be updated by app (column-level); immutability trigger blocks other columns
GRANT UPDATE (invalidated_at) ON public.refresh_idempotency_records TO dcmp_app;
GRANT SELECT, DELETE ON public.refresh_idempotency_records TO dcmp_cleanup;
GRANT EXECUTE ON FUNCTION public.invalidate_refresh_idempotency(UUID, UUID) TO dcmp_app;

-- Audit writer: INSERT only (Correction E)
REVOKE ALL ON public.security_events FROM PUBLIC;
REVOKE ALL ON public.security_events FROM dcmp_audit_writer;
GRANT INSERT ON public.security_events TO dcmp_audit_writer;
GRANT SELECT ON public.security_events TO dcmp_app;
GRANT SELECT ON public.security_events TO dcmp_platform_admin;

-- SECURITY DEFINER table grants
GRANT SELECT, INSERT, UPDATE ON dcmp_security.internal_keys TO dcmp_sec_definer;
GRANT SELECT, INSERT ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_grants TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_requests TO dcmp_sec_definer;

-- Function EXECUTE
REVOKE ALL ON FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM PUBLIC;
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) TO dcmp_platform_admin;
GRANT EXECUTE ON FUNCTION dcmp_security.verify_support_signature() TO dcmp_platform_admin;

-- Platform admin support RLS on users (after function exists)
DROP POLICY IF EXISTS padmin_users_p ON public.users;
DROP POLICY IF EXISTS padmin_users_r ON public.users;
CREATE POLICY padmin_users_p ON public.users AS PERMISSIVE FOR ALL TO dcmp_platform_admin
  USING (dcmp_security.verify_support_signature()) WITH CHECK (dcmp_security.verify_support_signature());
CREATE POLICY padmin_users_r ON public.users AS RESTRICTIVE FOR ALL TO dcmp_platform_admin
  USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
