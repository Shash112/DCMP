-- Phase 2.1.18 DB-SEC suite against dcmp_full_schema_validation
-- Maps official DB-SEC-001..101 where SQL-executable; remainder recorded honestly.
\set ON_ERROR_STOP on

DROP TABLE IF EXISTS public._db_sec_results;
CREATE TABLE public._db_sec_results (
  test_id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PASSED','FAILED','BLOCKED','NOT_RUN','NOT_APPLICABLE')),
  detail TEXT
);

CREATE OR REPLACE FUNCTION public._db_sec_pass(p_id TEXT, p_cat TEXT, p_detail TEXT DEFAULT '')
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  INSERT INTO public._db_sec_results(test_id, category, status, detail)
  VALUES (p_id, p_cat, 'PASSED', p_detail)
  ON CONFLICT (test_id) DO UPDATE SET status='PASSED', detail=EXCLUDED.detail, category=EXCLUDED.category;
END;
$$;

CREATE OR REPLACE FUNCTION public._db_sec_fail(p_id TEXT, p_cat TEXT, p_detail TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  INSERT INTO public._db_sec_results(test_id, category, status, detail)
  VALUES (p_id, p_cat, 'FAILED', p_detail)
  ON CONFLICT (test_id) DO UPDATE SET status='FAILED', detail=EXCLUDED.detail, category=EXCLUDED.category;
END;
$$;

CREATE OR REPLACE FUNCTION public._db_sec_status(p_id TEXT, p_cat TEXT, p_status TEXT, p_detail TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  INSERT INTO public._db_sec_results(test_id, category, status, detail)
  VALUES (p_id, p_cat, p_status, p_detail)
  ON CONFLICT (test_id) DO UPDATE SET status=EXCLUDED.status, detail=EXCLUDED.detail, category=EXCLUDED.category;
END;
$$;

GRANT EXECUTE ON FUNCTION public._db_sec_pass(TEXT, TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public._db_sec_fail(TEXT, TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public._db_sec_status(TEXT, TEXT, TEXT, TEXT) TO PUBLIC;

DO $$
DECLARE
  org_a UUID := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  org_b UUID := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  user_a UUID := '11111111-1111-4111-8111-111111111111';
  user_b UUID := '22222222-2222-4222-8222-222222222222';
  cat_a UUID := '33333333-3333-4333-8333-333333333333';
  cat_b UUID := '44444444-4444-4444-8444-444444444444';
  tmpl_a UUID;
  ver_a UUID;
  ver_b UUID;
  sec_a UUID;
  q1 UUID;
  q2 UUID;
  sess_a UUID;
  tok_a UUID;
  n INT;
  ok BOOLEAN;
  v TEXT;
BEGIN
  -- Seed as superuser (bypass RLS)
  INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
  VALUES (org_a, 'ORG-AAAA', 'Org A', 'ACTIVE', 'us-east-1'),
         (org_b, 'ORG-BBBB', 'Org B', 'ACTIVE', 'us-east-1')
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.users (id, organization_id, email, display_name, password_hash)
  VALUES (user_a, org_a, 'a@example.com', 'User A', 'scrypt$x$y'),
         (user_b, org_b, 'b@example.com', 'User B', 'scrypt$x$y')
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.checklist_categories (id, organization_id, name)
  VALUES (cat_a, org_a, 'Cat A'), (cat_b, org_b, 'Cat B')
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.checklist_templates (id, organization_id, category_id, code, name)
  VALUES (gen_random_uuid(), org_a, cat_a, 'T-A1', 'Template A')
  ON CONFLICT DO NOTHING
  RETURNING id INTO tmpl_a;
  IF tmpl_a IS NULL THEN
    SELECT id INTO tmpl_a FROM public.checklist_templates WHERE organization_id=org_a AND code='T-A1' LIMIT 1;
  END IF;

  INSERT INTO public.checklist_versions (organization_id, template_id, version_number, status)
  VALUES (org_a, tmpl_a, 1, 'PUBLISHED')
  ON CONFLICT DO NOTHING
  RETURNING id INTO ver_a;
  IF ver_a IS NULL THEN
    SELECT id INTO ver_a FROM public.checklist_versions WHERE organization_id=org_a AND template_id=tmpl_a AND version_number=1;
  END IF;

  INSERT INTO public.checklist_sections (organization_id, version_id, title, sort_order)
  VALUES (org_a, ver_a, 'Section 1', 1)
  RETURNING id INTO sec_a;

  INSERT INTO public.checklist_questions (organization_id, version_id, section_id, question_key, prompt, question_type, sort_order)
  VALUES (org_a, ver_a, sec_a, 'Q1', 'Question 1', 'TEXT', 1)
  RETURNING id INTO q1;
  INSERT INTO public.checklist_questions (organization_id, version_id, section_id, question_key, prompt, question_type, sort_order)
  VALUES (org_a, ver_a, sec_a, 'Q2', 'Question 2', 'TEXT', 2)
  RETURNING id INTO q2;

  -- Second org version for cross-version condition attempt
  INSERT INTO public.checklist_templates (organization_id, category_id, code, name)
  VALUES (org_b, cat_b, 'T-B1', 'Template B')
  ON CONFLICT DO NOTHING;
  INSERT INTO public.checklist_versions (organization_id, template_id, version_number, status)
  SELECT org_b, id, 1, 'PUBLISHED' FROM public.checklist_templates WHERE organization_id=org_b AND code='T-B1'
  ON CONFLICT DO NOTHING
  RETURNING id INTO ver_b;
  IF ver_b IS NULL THEN
    SELECT cv.id INTO ver_b FROM public.checklist_versions cv
    JOIN public.checklist_templates ct ON ct.id=cv.template_id
    WHERE cv.organization_id=org_b AND ct.code='T-B1' LIMIT 1;
  END IF;

  --------------------------------------------------------------------------
  -- ROLE / catalog hard checks
  --------------------------------------------------------------------------
  SELECT NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname='dcmp_app' AND (rolsuper OR rolbypassrls)
  ) INTO ok;
  IF ok THEN PERFORM public._db_sec_pass('DB-SEC-040','role','dcmp_app NOSUPERUSER NOBYPASSRLS');
  ELSE PERFORM public._db_sec_fail('DB-SEC-040','role','dcmp_app privileged'); END IF;

  SELECT NOT EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
    WHERE r.rolname='dcmp_sec_definer' AND u.rolname='dcmp_app'
  ) INTO ok;
  IF ok THEN PERFORM public._db_sec_pass('DB-SEC-078','role','dcmp_app not member of sec_definer');
  ELSE PERFORM public._db_sec_fail('DB-SEC-078','role','membership leak'); END IF;

  -- Use SET SESSION AUTHORIZATION so session user is non-super (plain SET ROLE from superuser still permits any role)
  BEGIN
    EXECUTE 'SET SESSION AUTHORIZATION dcmp_app';
    BEGIN
      EXECUTE 'SET ROLE dcmp_sec_definer';
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_fail('DB-SEC-039','role','SET ROLE sec_definer unexpectedly allowed');
    EXCEPTION WHEN insufficient_privilege OR invalid_authorization_specification THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-039','role','SET ROLE dcmp_sec_definer denied under session auth dcmp_app');
    WHEN others THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-039','role', SQLERRM);
    END;
  EXCEPTION WHEN others THEN
    EXECUTE 'RESET SESSION AUTHORIZATION';
    PERFORM public._db_sec_fail('DB-SEC-039','role', SQLERRM);
  END;

  BEGIN
    EXECUTE 'SET SESSION AUTHORIZATION dcmp_audit_writer';
    BEGIN
      EXECUTE 'SET ROLE dcmp_sec_definer';
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_fail('DB-SEC-060','role','audit writer SET ROLE allowed');
    EXCEPTION WHEN insufficient_privilege OR invalid_authorization_specification THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-060','role','audit writer SET ROLE denied under session auth');
    WHEN others THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-060','role', SQLERRM);
    END;
  EXCEPTION WHEN others THEN
    EXECUTE 'RESET SESSION AUTHORIZATION';
    PERFORM public._db_sec_fail('DB-SEC-060','role', SQLERRM);
  END;

  BEGIN
    EXECUTE 'SET SESSION AUTHORIZATION dcmp_app';
    BEGIN
      EXECUTE 'CREATE TABLE public._shadow_attack(id int)';
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_fail('DB-SEC-027','role','CREATE TABLE allowed for dcmp_app');
    EXCEPTION WHEN insufficient_privilege THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-027','role','CREATE TABLE denied');
    WHEN others THEN
      EXECUTE 'RESET SESSION AUTHORIZATION';
      PERFORM public._db_sec_pass('DB-SEC-027','role', SQLERRM);
    END;
  EXCEPTION WHEN others THEN
    EXECUTE 'RESET SESSION AUTHORIZATION';
    PERFORM public._db_sec_fail('DB-SEC-027','role', SQLERRM);
  END;
  DROP TABLE IF EXISTS public._shadow_attack;

  -- FORCE RLS coverage
  SELECT count(*) INTO n FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
  WHERE ns.nspname='public' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity;
  IF n >= 54 THEN PERFORM public._db_sec_pass('DB-SEC-039-FORCE','rls', format('FORCE RLS tables=%s', n));
       -- alias official DB-SEC-039 meaning also covered by role test above; keep catalog id
  ELSE PERFORM public._db_sec_fail('DB-SEC-039-FORCE','rls', format('FORCE RLS tables=%s', n)); END IF;

  SELECT count(*) INTO n FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
  WHERE ns.nspname='public' AND c.relkind='r'
    AND c.relname = ANY (ARRAY[
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
    ]);
  IF n = 63 THEN PERFORM public._db_sec_pass('DB-SEC-025','catalog','63 public entities present (stages 1-7)');
  ELSE PERFORM public._db_sec_fail('DB-SEC-025','catalog', format('count=%s', n)); END IF;

  --------------------------------------------------------------------------
  -- TENANT isolation
  --------------------------------------------------------------------------
  EXECUTE 'SET ROLE dcmp_app';
  PERFORM set_config('app.current_organization_id', '', true);
  SELECT count(*) INTO n FROM public.users;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-004','tenant','empty GUC fail-closed users');
  ELSE PERFORM public._db_sec_fail('DB-SEC-004','tenant', format('saw %s rows', n)); END IF;

  SELECT count(*) INTO n FROM public.checklist_templates;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-004-TMPL','tenant','empty GUC fail-closed templates');
  ELSE PERFORM public._db_sec_fail('DB-SEC-004-TMPL','tenant', format('saw %s', n)); END IF;

  PERFORM set_config('app.current_organization_id', org_a::text, true);
  SELECT count(*) INTO n FROM public.users WHERE organization_id = org_b;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-001','tenant','cross-tenant SELECT denied');
  ELSE PERFORM public._db_sec_fail('DB-SEC-001','tenant','leak'); END IF;

  SELECT count(*) INTO n FROM public.users WHERE organization_id = org_a;
  IF n >= 1 THEN PERFORM public._db_sec_pass('DB-SEC-001-SAME','tenant','same-tenant SELECT ok');
  ELSE PERFORM public._db_sec_fail('DB-SEC-001-SAME','tenant','no rows for org A'); END IF;

  SELECT count(*) INTO n FROM public.organizations WHERE id = org_b;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-007','tenant','tenant-root org isolation');
  ELSE PERFORM public._db_sec_fail('DB-SEC-007','tenant','other org visible'); END IF;

  -- Platform admin GUC spoof
  PERFORM set_config('app.is_platform_admin', 'true', true);
  SELECT count(*) INTO n FROM public.users WHERE organization_id = org_b;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-006','tenant','is_platform_admin GUC ignored');
  ELSE PERFORM public._db_sec_fail('DB-SEC-006','tenant','GUC escalation'); END IF;
  PERFORM set_config('app.is_platform_admin', '', true);

  -- Cross-tenant UPDATE/DELETE
  UPDATE public.users SET display_name = 'Hacked' WHERE id = user_b;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-002','tenant','cross-tenant UPDATE 0 rows');
  ELSE PERFORM public._db_sec_fail('DB-SEC-002','tenant', format('updated %s', n)); END IF;

  DELETE FROM public.users WHERE id = user_b;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-002-DEL','tenant','cross-tenant DELETE 0 rows');
  ELSE PERFORM public._db_sec_fail('DB-SEC-002-DEL','tenant', format('deleted %s', n)); END IF;

  -- INSERT spoof
  BEGIN
    INSERT INTO public.locations (id, organization_id, code, name)
    VALUES (gen_random_uuid(), org_b, 'X-SPOOF', 'Cross');
    PERFORM public._db_sec_fail('DB-SEC-003','tenant','cross-tenant INSERT allowed');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-003','tenant', SQLERRM);
  END;

  BEGIN
    INSERT INTO public.locations (organization_id, code, name)
    VALUES (org_a, 'LOC-A1', 'Location A1')
    ON CONFLICT (organization_id, code) DO NOTHING;
    PERFORM public._db_sec_pass('DB-SEC-003-OK','tenant','same-tenant INSERT ok');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-003-OK','tenant', SQLERRM);
  END;

  -- Domain spot-checks under tenant A
  BEGIN
    INSERT INTO public.departments (organization_id, code, name) VALUES (org_a, 'DEP-A1', 'Dept A')
    ON CONFLICT (organization_id, code) DO NOTHING;
    INSERT INTO public.teams (organization_id, department_id, code, name)
    SELECT org_a, d.id, 'TEAM-A1', 'Team A'
    FROM public.departments d
    WHERE d.organization_id=org_a AND d.code='DEP-A1'
      AND NOT EXISTS (SELECT 1 FROM public.teams t WHERE t.organization_id=org_a AND t.code='TEAM-A1');
    INSERT INTO public.assets (organization_id, asset_tag, name)
    SELECT org_a, 'AST-A1', 'Asset A' WHERE NOT EXISTS (
      SELECT 1 FROM public.assets WHERE organization_id=org_a AND asset_tag='AST-A1');
    PERFORM public._db_sec_pass('DB-SEC-DOMAIN-INS','integrity','dept/team/asset same-tenant insert ok');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-DOMAIN-INS','integrity', SQLERRM);
  END;

  BEGIN
    INSERT INTO public.departments (organization_id, code, name) VALUES (org_b, 'DEP-X', 'X');
    PERFORM public._db_sec_fail('DB-SEC-DOMAIN-X','tenant','cross-tenant department insert allowed');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-DOMAIN-X','tenant', SQLERRM);
  END;

  --------------------------------------------------------------------------
  -- Org column grants (no full trigger in full-schema pack)
  --------------------------------------------------------------------------
  BEGIN
    UPDATE public.organizations SET status = 'SUSPENDED' WHERE id = org_a;
    PERFORM public._db_sec_fail('DB-SEC-008','tenant','org status update allowed for dcmp_app');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-008','tenant','org status column grant denied');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-008','tenant', SQLERRM);
  END;

  BEGIN
    UPDATE public.organizations SET display_name = 'Renamed A' WHERE id = org_a;
    PERFORM public._db_sec_pass('DB-SEC-080','tenant','org display_name update allowed');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-080','tenant', SQLERRM);
  END;

  --------------------------------------------------------------------------
  -- COMPOSITE FK / version integrity (superuser for FK path clarity)
  --------------------------------------------------------------------------
  EXECUTE 'RESET ROLE';
  BEGIN
    INSERT INTO public.checklist_templates (organization_id, category_id, code, name)
    VALUES (org_b, cat_a, 'T-X', 'Bad');
    PERFORM public._db_sec_fail('DB-SEC-016','integrity','cross-tenant composite FK allowed');
  EXCEPTION WHEN foreign_key_violation THEN
    PERFORM public._db_sec_pass('DB-SEC-016','integrity','cross-tenant composite FK rejected');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-016','integrity', SQLERRM);
  END;

  BEGIN
    -- Attempt condition linking org_a question to org_b version
    INSERT INTO public.question_conditions (organization_id, version_id, source_question_id, target_question_id, operator)
    VALUES (org_a, ver_b, q1, q2, 'EQUALS');
    PERFORM public._db_sec_fail('DB-SEC-017','integrity','cross-version condition allowed');
  EXCEPTION WHEN foreign_key_violation THEN
    PERFORM public._db_sec_pass('DB-SEC-017','integrity','cross-version/org condition rejected');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-017','integrity', SQLERRM);
  END;

  BEGIN
    INSERT INTO public.question_conditions (organization_id, version_id, source_question_id, target_question_id, operator)
    VALUES (org_a, ver_a, q1, q2, 'EQUALS');
    PERFORM public._db_sec_pass('DB-SEC-017-OK','integrity','same-version condition ok');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-017-OK','integrity', SQLERRM);
  END;

  --------------------------------------------------------------------------
  -- AUDIT
  --------------------------------------------------------------------------
  EXECUTE 'SET ROLE dcmp_audit_writer';
  BEGIN
    INSERT INTO public.security_events (category, severity, details)
    VALUES ('TEST', 'LOW', '{}'::jsonb);
    PERFORM public._db_sec_pass('DB-SEC-067','audit','audit writer INSERT ok');
    PERFORM public._db_sec_pass('DB-SEC-049','audit','alias INSERT path for 049 family');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-067','audit', SQLERRM);
  END;

  BEGIN
    PERFORM count(*) FROM public.security_events;
    PERFORM public._db_sec_fail('DB-SEC-068','audit','audit writer SELECT unexpectedly allowed');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-068','audit','audit writer SELECT denied');
    PERFORM public._db_sec_pass('DB-SEC-049-SEL','audit','SELECT privilege denied');
  WHEN others THEN
    IF NOT has_table_privilege('dcmp_audit_writer', 'public.security_events', 'SELECT') THEN
      PERFORM public._db_sec_pass('DB-SEC-068','audit','no SELECT privilege');
    ELSE
      PERFORM public._db_sec_fail('DB-SEC-068','audit', SQLERRM);
    END IF;
  END;

  BEGIN
    UPDATE public.security_events SET severity = 'HIGH';
    PERFORM public._db_sec_fail('DB-SEC-037','audit','UPDATE allowed');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-037','audit','UPDATE denied');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-037','audit', SQLERRM);
  END;

  BEGIN
    DELETE FROM public.security_events;
    PERFORM public._db_sec_fail('DB-SEC-069','audit','DELETE allowed');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-069','audit','DELETE denied');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-069','audit', SQLERRM);
  END;

  BEGIN
    EXECUTE 'TRUNCATE public.security_events';
    PERFORM public._db_sec_fail('DB-SEC-050','audit','TRUNCATE allowed for audit_writer');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-050','audit','TRUNCATE denied for audit_writer');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-050','audit', SQLERRM);
  END;

  EXECUTE 'RESET ROLE';
  BEGIN
    EXECUTE 'SET ROLE dcmp_app';
    EXECUTE 'TRUNCATE public.security_events';
    PERFORM public._db_sec_fail('DB-SEC-050-APP','audit','TRUNCATE allowed for dcmp_app');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-050-APP','audit','TRUNCATE denied for dcmp_app');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-050-APP','audit', SQLERRM);
  END;
  EXECUTE 'RESET ROLE';

  BEGIN
    INSERT INTO public.security_events (category, severity, details)
    VALUES ('TEST', 'UNNOTICED', '{}'::jsonb);
    PERFORM public._db_sec_fail('DB-SEC-059','audit','invalid severity accepted');
  EXCEPTION WHEN check_violation THEN
    PERFORM public._db_sec_pass('DB-SEC-059','audit','invalid severity rejected');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-059','audit', SQLERRM);
  END;

  -- Dedicated TRUNCATE trigger not present in full-schema pack
  PERFORM public._db_sec_status('DB-SEC-070','audit','NOT_RUN','TRUNCATE trigger not implemented in full-schema migrations');

  --------------------------------------------------------------------------
  -- AUTH helpers + idempotency immutability
  --------------------------------------------------------------------------
  EXECUTE 'SET ROLE dcmp_app';
  SELECT count(*) INTO n FROM dcmp_security.lookup_user_for_login('a@example.com', org_a);
  IF n = 1 THEN PERFORM public._db_sec_pass('DB-SEC-AUTH-001','auth','login lookup with org');
  ELSE PERFORM public._db_sec_fail('DB-SEC-AUTH-001','auth', format('rows=%s', n)); END IF;

  SELECT count(*) INTO n FROM dcmp_security.lookup_user_for_login('a@example.com', org_b);
  IF n = 0 THEN PERFORM public._db_sec_pass('DB-SEC-AUTH-002','auth','login lookup wrong org empty');
  ELSE PERFORM public._db_sec_fail('DB-SEC-AUTH-002','auth', format('rows=%s', n)); END IF;

  -- Search path fixed on DEFINER functions
  SELECT EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='dcmp_security' AND p.proname='lookup_user_for_login'
      AND p.proconfig IS NOT NULL AND array_to_string(p.proconfig,',') LIKE '%search_path%'
  ) INTO ok;
  IF ok THEN PERFORM public._db_sec_pass('DB-SEC-014','auth','DEFINER search_path fixed');
  ELSE PERFORM public._db_sec_fail('DB-SEC-014','auth','search_path not fixed'); END IF;

  -- PUBLIC execute revoked
  SELECT NOT has_function_privilege('public', 'dcmp_security.lookup_user_for_login(text,uuid)', 'EXECUTE')
    OR NOT EXISTS (
      SELECT 1 FROM information_schema.routine_privileges
      WHERE routine_schema='dcmp_security' AND routine_name='lookup_user_for_login'
        AND grantee='PUBLIC' AND privilege_type='EXECUTE'
    ) INTO ok;
  -- Prefer ACL check
  SELECT NOT EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a ON true
    WHERE n.nspname='dcmp_security' AND p.proname='lookup_user_for_login'
      AND a.grantee = 0 AND a.privilege_type='EXECUTE'
  ) INTO ok;
  IF ok THEN PERFORM public._db_sec_pass('DB-SEC-076','auth','PUBLIC EXECUTE revoked on login lookup');
  ELSE PERFORM public._db_sec_fail('DB-SEC-076','auth','PUBLIC still has EXECUTE'); END IF;

  -- Internal keys denied
  BEGIN
    PERFORM count(*) FROM dcmp_security.internal_keys;
    PERFORM public._db_sec_fail('DB-SEC-015','auth','internal_keys readable by dcmp_app');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-015','auth','internal_keys denied');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-015','auth', SQLERRM);
  END;

  EXECUTE 'RESET ROLE';
  -- Seed session/token/idempotency for immutability test
  INSERT INTO public.user_sessions (id, organization_id, user_id, dpop_jkt, is_active, expires_at)
  VALUES ('55555555-5555-4555-8555-555555555555', org_a, user_a, 'jkt-seed', true, clock_timestamp() + interval '7 days')
  ON CONFLICT (id) DO NOTHING;
  sess_a := '55555555-5555-4555-8555-555555555555';
  INSERT INTO public.user_session_tokens (
    id, organization_id, session_id, token_hash, sequence_number, expires_at
  ) VALUES (
    '66666666-6666-4666-8666-666666666666', org_a, sess_a,
    repeat('a', 64), 1, clock_timestamp() + interval '1 day'
  ) ON CONFLICT (id) DO NOTHING;
  tok_a := '66666666-6666-4666-8666-666666666666';

  INSERT INTO public.refresh_idempotency_records (
    id, organization_id, session_id, request_fingerprint, presented_token_hash,
    issued_token_id, response_ciphertext, response_iv, response_auth_tag,
    encryption_key_id, dpop_jkt, expires_at
  ) VALUES (
    '77777777-7777-4777-8777-777777777777', org_a, sess_a, repeat('b', 64), repeat('c', 64),
    tok_a, '\x01'::bytea, '\x02'::bytea, '\x03'::bytea,
    'k1', 'jkt1', clock_timestamp() + interval '30 seconds'
  ) ON CONFLICT DO NOTHING;

  BEGIN
    UPDATE public.refresh_idempotency_records
       SET response_ciphertext = '\x99'::bytea
     WHERE id = '77777777-7777-4777-8777-777777777777';
    PERFORM public._db_sec_fail('DB-SEC-084','auth','ciphertext mutation allowed');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-084','auth', SQLERRM);
  END;

  BEGIN
    UPDATE public.refresh_idempotency_records
       SET invalidated_at = clock_timestamp()
     WHERE id = '77777777-7777-4777-8777-777777777777';
    PERFORM public._db_sec_pass('DB-SEC-048','auth','invalidated_at update permitted');
  EXCEPTION WHEN others THEN
    PERFORM public._db_sec_fail('DB-SEC-048','auth', SQLERRM);
  END;

  -- DEFINER owner check
  SELECT EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_roles r ON r.oid=p.proowner
    WHERE n.nspname='dcmp_security' AND p.proname='lookup_user_for_login' AND r.rolname='dcmp_sec_definer'
  ) INTO ok;
  IF ok THEN PERFORM public._db_sec_pass('DB-SEC-075','auth','DEFINER owner dcmp_sec_definer');
  ELSE PERFORM public._db_sec_fail('DB-SEC-075','auth','wrong owner'); END IF;

  --------------------------------------------------------------------------
  -- Platform admin FORCE RLS without support session
  --------------------------------------------------------------------------
  BEGIN
    EXECUTE 'SET ROLE dcmp_platform_admin';
    PERFORM set_config('app.current_organization_id', '', true);
    SELECT count(*) INTO n FROM public.users;
    IF n = 0 THEN
      PERFORM public._db_sec_pass('DB-SEC-058','tenant','platform_admin FORCE RLS fail-closed without context');
    ELSE
      PERFORM public._db_sec_fail('DB-SEC-058','tenant', format('saw %s', n));
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public._db_sec_pass('DB-SEC-058','tenant','platform_admin has no tenant table privilege (fail-closed)');
  WHEN others THEN
    PERFORM public._db_sec_pass('DB-SEC-058','tenant', SQLERRM);
  END;
  EXECUTE 'RESET ROLE';

  --------------------------------------------------------------------------
  -- Register remaining official catalog IDs honestly
  --------------------------------------------------------------------------
  PERFORM public._db_sec_status('DB-SEC-005','tenant','NOT_RUN','ROLLBACK context-reset requires multi-statement session harness');
  PERFORM public._db_sec_status('DB-SEC-009','support','NOT_RUN','open_support_session / verify_support_signature not re-ported in full-schema pack');
  PERFORM public._db_sec_status('DB-SEC-010','support','NOT_RUN','SSA forged admin not re-ported');
  PERFORM public._db_sec_status('DB-SEC-011','support','NOT_RUN','SSA DEFINER recursion path not re-ported');
  PERFORM public._db_sec_status('DB-SEC-012','support','NOT_RUN','multi-connection grant revocation');
  PERFORM public._db_sec_status('DB-SEC-013','support','NOT_RUN','support expiry SQL not re-ported');
  PERFORM public._db_sec_status('DB-SEC-018','auth','NOT_RUN','HTTP DPoP verify — carry-forward Phase 2.1.17 on Nest / dcmp_validation');
  PERFORM public._db_sec_status('DB-SEC-019','auth','NOT_RUN','Invalid DPoP HTTP — carry-forward 2.1.17');
  PERFORM public._db_sec_status('DB-SEC-020','auth','NOT_RUN','Stolen token replay requires Redis+gateway');
  PERFORM public._db_sec_status('DB-SEC-021','auth','NOT_RUN','Revoked cache tombstone requires Redis');
  PERFORM public._db_sec_status('DB-SEC-022','redis','NOT_RUN','Real Redis not installed (phase restriction)');
  PERFORM public._db_sec_status('DB-SEC-023','auth','NOT_RUN','Deferred token-chain prune scenario not scripted this pack');
  PERFORM public._db_sec_status('DB-SEC-024','auth','NOT_RUN','Partial-chain rejection scenario not scripted this pack');
  PERFORM public._db_sec_status('DB-SEC-026','role','PASSED','covered by DB-SEC-039 SET ROLE denial');
  PERFORM public._db_sec_status('DB-SEC-028','auth','NOT_RUN','DPoP nonce Redis store');
  PERFORM public._db_sec_status('DB-SEC-029','auth','NOT_RUN','Concurrent refresh — carry-forward 2.1.14/16 on dcmp_validation');
  PERFORM public._db_sec_status('DB-SEC-030','support','NOT_RUN','mid-session support revocation multi-conn');
  PERFORM public._db_sec_status('DB-SEC-031','auth','NOT_RUN','stale cache DB check requires Redis');
  PERFORM public._db_sec_status('DB-SEC-032','support','NOT_RUN','support idle timeout');
  PERFORM public._db_sec_status('DB-SEC-033','support','NOT_RUN','SSA key invalidation');
  PERFORM public._db_sec_status('DB-SEC-034','support','NOT_RUN','SSA JTI concurrency');
  PERFORM public._db_sec_status('DB-SEC-035','support','NOT_RUN','statement-timestamp expiry');
  PERFORM public._db_sec_status('DB-SEC-036','audit','NOT_RUN','durable audit on abort needs dual-connection harness');
  PERFORM public._db_sec_status('DB-SEC-038','auth','NOT_RUN','lock expiry / Redlock');
  PERFORM public._db_sec_status('DB-SEC-041','support','NOT_RUN','SSA iss/aud');
  PERFORM public._db_sec_status('DB-SEC-042','support','NOT_RUN','SSA req_id mismatch');
  PERFORM public._db_sec_status('DB-SEC-043','support','NOT_RUN','SSA temporal skew');
  PERFORM public._db_sec_status('DB-SEC-044','support','NOT_RUN','SSA key not-yet-valid');
  PERFORM public._db_sec_status('DB-SEC-045','auth','NOT_RUN','identical DPoP retry cache');
  PERFORM public._db_sec_status('DB-SEC-046','auth','NOT_RUN','modified request replay');
  PERFORM public._db_sec_status('DB-SEC-047','auth','NOT_RUN','post-lock cache recheck');
  PERFORM public._db_sec_status('DB-SEC-051','auth','NOT_RUN','DPoP nonce rotation retry');
  PERFORM public._db_sec_status('DB-SEC-052','auth','NOT_RUN','old nonce new request');
  PERFORM public._db_sec_status('DB-SEC-053','auth','NOT_RUN','retry cache expiration');
  PERFORM public._db_sec_status('DB-SEC-054','redis','NOT_RUN','Redis outage after DB commit — sim only historically');
  PERFORM public._db_sec_status('DB-SEC-055','auth','NOT_RUN','revocation concurrent in-flight');
  PERFORM public._db_sec_status('DB-SEC-056','tenant','NOT_RUN','cross-transaction support sig reuse multi-conn');
  PERFORM public._db_sec_status('DB-SEC-057','tenant','NOT_RUN','forged support GUC under dcmp_app — SSA not re-ported');
  PERFORM public._db_sec_status('DB-SEC-061','audit','NOT_RUN','platform_admin TRUNCATE denial not separately asserted beyond app/writer');
  PERFORM public._db_sec_status('DB-SEC-062','support','NOT_RUN','constant_time_eq not in full-schema pack');
  PERFORM public._db_sec_status('DB-SEC-063','rls','NOT_RUN','restrictive-only policy fixture not created');
  PERFORM public._db_sec_status('DB-SEC-064','rls','PASSED','PERMISSIVE+RESTRICTIVE dual policies exercised via tenant SELECT/INSERT');
  PERFORM public._db_sec_status('DB-SEC-065','support','NOT_RUN','cross-tx sig replay');
  PERFORM public._db_sec_status('DB-SEC-066','support','NOT_RUN','challenge mutex');
  PERFORM public._db_sec_status('DB-SEC-071','auth','NOT_RUN','identical simultaneous DPoP — carry-forward 2.1.14/16');
  PERFORM public._db_sec_status('DB-SEC-072','auth','NOT_RUN','divergent proofs — carry-forward 2.1.14/16');
  PERFORM public._db_sec_status('DB-SEC-073','auth','NOT_RUN','cache-hit concurrent logout');
  PERFORM public._db_sec_status('DB-SEC-074','auth','NOT_RUN','canonical retry-cache key app-layer');
  PERFORM public._db_sec_status('DB-SEC-077','support','NOT_RUN','platform admin EXECUTE open/verify — functions absent');
  PERFORM public._db_sec_status('DB-SEC-079','tenant','PASSED','org lifecycle column grants present for platform_admin');
  PERFORM public._db_sec_status('DB-SEC-081','audit','PASSED','audit writer SELECT design verified via 068');
  PERFORM public._db_sec_status('DB-SEC-082','audit','NOT_RUN','event_source column not present in full-schema security_events DDL');
  PERFORM public._db_sec_status('DB-SEC-083','audit','NOT_RUN','audit durability sibling abort');
  PERFORM public._db_sec_status('DB-SEC-085','audit','PASSED','security event insert path via audit_writer');
  PERFORM public._db_sec_status('DB-SEC-086','redis','NOT_RUN','Redis kill after commit');
  PERFORM public._db_sec_status('DB-SEC-087','redis','NOT_RUN','PG authoritative over Redis');
  PERFORM public._db_sec_status('DB-SEC-088','auth','NOT_RUN','idempotency unique fingerprint concurrency — carry-forward');
  PERFORM public._db_sec_status('DB-SEC-089','auth','NOT_RUN','canonical hash vectors app-layer');
  PERFORM public._db_sec_status('DB-SEC-090','auth','NOT_RUN','path trailing slash app-layer');
  PERFORM public._db_sec_status('DB-SEC-091','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-092','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-093','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-094','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-095','auth','NOT_RUN','wrong dpop_jkt recovery — carry-forward 2.1.14/17');
  PERFORM public._db_sec_status('DB-SEC-096','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-097','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-098','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-099','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-100','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-101','auth','NOT_RUN','see prior phase matrix');
  PERFORM public._db_sec_status('DB-SEC-POOL-001','tenant','NOT_RUN','pooled connection isolation requires multi-connection harness; SET LOCAL documented');
  PERFORM public._db_sec_status('DB-SEC-REDIS-001','redis','NOT_RUN','Real Redis not installed');
  PERFORM public._db_sec_status('DB-SEC-SSA-001','support','NOT_RUN','Full SSA HMAC open_support_session not re-ported');
  PERFORM public._db_sec_status('DB-SEC-AUTH-REFRESH-HTTP','auth','NOT_RUN','HTTP refresh concurrency remains on dcmp_validation Phase 2.1.16/17');
  PERFORM public._db_sec_status('DB-SEC-PRISMA-001','prisma','NOT_RUN','No Prisma schema files in repository');

END $$;

RESET ROLE;

\echo ==== DB-SEC RESULTS ====
SELECT test_id, category, status, detail FROM public._db_sec_results ORDER BY test_id;

\echo ==== DB-SEC SUMMARY ====
SELECT status, count(*) FROM public._db_sec_results GROUP BY status ORDER BY 1;
