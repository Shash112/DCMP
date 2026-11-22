-- Phase 2.1.19 / S12 — FORCE RLS policies for SSA SECURITY DEFINER reads + schema USAGE
\set ON_ERROR_STOP on

GRANT USAGE ON SCHEMA dcmp_security TO dcmp_platform_admin;
GRANT USAGE ON SCHEMA dcmp_security TO dcmp_sec_definer;

DROP POLICY IF EXISTS sec_definer_support_grants_sel ON public.support_access_grants;
CREATE POLICY sec_definer_support_grants_sel ON public.support_access_grants
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);

DROP POLICY IF EXISTS sec_definer_support_reqs_sel ON public.support_access_requests;
CREATE POLICY sec_definer_support_reqs_sel ON public.support_access_requests
  AS PERMISSIVE FOR SELECT TO dcmp_sec_definer USING (true);

\echo NOTICE: S12_ssa_definer_policies OK
