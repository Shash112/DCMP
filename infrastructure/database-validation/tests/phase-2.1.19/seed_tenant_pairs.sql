-- Seed minimal org A/B rows for RLS54 coverage on dcmp_full_schema_validation
\set ON_ERROR_STOP on

INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ORG-AAAA','Org A','ACTIVE','us-east-1'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','ORG-BBBB','Org B','ACTIVE','us-east-1')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.users (id, organization_id, email, display_name, password_hash)
VALUES
  ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','a@example.com','User A','scrypt$x$y'),
  ('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','b@example.com','User B','scrypt$x$y')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organization_domains (organization_id, hostname, is_primary)
VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','org-a.example.test', true),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','org-b.example.test', true)
ON CONFLICT (hostname) DO NOTHING;

INSERT INTO public.organization_settings (organization_id, settings)
VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','{}'::jsonb),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','{}'::jsonb)
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO public.locations (organization_id, code, name) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','LOC-A','Location A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','LOC-B','Location B')
ON CONFLICT (organization_id, code) DO NOTHING;

INSERT INTO public.departments (organization_id, code, name) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','DEP-A','Dept A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','DEP-B','Dept B')
ON CONFLICT (organization_id, code) DO NOTHING;

INSERT INTO public.teams (organization_id, department_id, code, name)
SELECT o.organization_id, d.id, o.code, o.name
FROM (VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'DEP-A','TEAM-A','Team A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'DEP-B','TEAM-B','Team B')
) AS o(organization_id, dep_code, code, name)
JOIN public.departments d ON d.organization_id=o.organization_id AND d.code=o.dep_code
ON CONFLICT (organization_id, code) DO NOTHING;

INSERT INTO public.roles (organization_id, name) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ROLE-A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','ROLE-B')
ON CONFLICT (organization_id, name) DO NOTHING;

INSERT INTO public.permissions (key) VALUES ('perm.a'),('perm.b') ON CONFLICT DO NOTHING;

INSERT INTO public.role_permissions (organization_id, role_id, permission_id)
SELECT r.organization_id, r.id, p.id
FROM public.roles r
JOIN public.permissions p ON (r.name='ROLE-A' AND p.key='perm.a') OR (r.name='ROLE-B' AND p.key='perm.b')
ON CONFLICT DO NOTHING;

INSERT INTO public.user_roles (organization_id, user_id, role_id)
SELECT r.organization_id, u.id, r.id
FROM public.roles r
JOIN public.users u ON u.organization_id=r.organization_id
WHERE r.name IN ('ROLE-A','ROLE-B')
ON CONFLICT DO NOTHING;

INSERT INTO public.user_organizational_assignments (organization_id, user_id, location_id, department_id, team_id, is_primary)
SELECT u.organization_id, u.id, l.id, d.id, t.id, true
FROM public.users u
JOIN public.locations l ON l.organization_id=u.organization_id
JOIN public.departments d ON d.organization_id=u.organization_id
JOIN public.teams t ON t.organization_id=u.organization_id
WHERE u.id IN ('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222')
  AND NOT EXISTS (
    SELECT 1 FROM public.user_organizational_assignments x WHERE x.user_id=u.id
  );

INSERT INTO public.assets (organization_id, asset_tag, name) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','AST-A','Asset A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','AST-B','Asset B')
ON CONFLICT (organization_id, asset_tag) DO NOTHING;

INSERT INTO public.license_plans (code, name) VALUES ('PLAN-A','Plan A'),('PLAN-B','Plan B')
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.customer_licenses (organization_id, plan_id, license_key_hash, status, starts_at)
SELECT o.org, p.id, o.hash, 'ACTIVE', now()
FROM (VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'PLAN-A','hash-a'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'PLAN-B','hash-b')
) AS o(org, plan_code, hash)
JOIN public.license_plans p ON p.code=o.plan_code
ON CONFLICT (license_key_hash) DO NOTHING;

INSERT INTO public.license_events (organization_id, license_id, event_type)
SELECT cl.organization_id, cl.id, 'ASSIGNED'
FROM public.customer_licenses cl
WHERE NOT EXISTS (
  SELECT 1 FROM public.license_events le WHERE le.license_id=cl.id
);

INSERT INTO public.mobile_devices (organization_id, installation_id_hash, platform) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','install-a','ANDROID'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','install-b','ANDROID')
ON CONFLICT (installation_id_hash) DO NOTHING;

INSERT INTO public.device_user_sessions (organization_id, device_id, user_id)
SELECT md.organization_id, md.id, u.id
FROM public.mobile_devices md
JOIN public.users u ON u.organization_id=md.organization_id
WHERE md.installation_id_hash IN ('install-a','install-b')
  AND NOT EXISTS (
    SELECT 1 FROM public.device_user_sessions dus WHERE dus.device_id=md.id AND dus.user_id=u.id
  );

INSERT INTO public.checklist_categories (organization_id, name) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','Cat A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','Cat B')
ON CONFLICT (organization_id, name) DO NOTHING;

INSERT INTO public.checklist_templates (organization_id, category_id, code, name)
SELECT c.organization_id, c.id, CASE WHEN c.name='Cat A' THEN 'T-A' ELSE 'T-B' END, c.name
FROM public.checklist_categories c
ON CONFLICT (organization_id, code) DO NOTHING;

INSERT INTO public.checklist_versions (organization_id, template_id, version_number, status)
SELECT t.organization_id, t.id, 1, 'PUBLISHED'
FROM public.checklist_templates t
ON CONFLICT (template_id, version_number) DO NOTHING;

INSERT INTO public.checklist_sections (organization_id, version_id, title, sort_order)
SELECT v.organization_id, v.id, 'Section 1', 1
FROM public.checklist_versions v
WHERE NOT EXISTS (
  SELECT 1 FROM public.checklist_sections s WHERE s.version_id=v.id
);

INSERT INTO public.checklist_questions (organization_id, version_id, section_id, question_key, prompt, question_type, sort_order)
SELECT s.organization_id, s.version_id, s.id, 'Q1', 'Prompt', 'TEXT', 1
FROM public.checklist_sections s
ON CONFLICT (section_id, question_key) DO NOTHING;

INSERT INTO public.question_options (organization_id, question_id, option_key, label)
SELECT q.organization_id, q.id, 'O1', 'Opt'
FROM public.checklist_questions q
ON CONFLICT (question_id, option_key) DO NOTHING;

INSERT INTO public.question_conditions (organization_id, version_id, source_question_id, target_question_id, operator)
SELECT q.organization_id, q.version_id, q.id, q.id, 'EQUALS'
FROM public.checklist_questions q
WHERE NOT EXISTS (
  SELECT 1 FROM public.question_conditions qc WHERE qc.source_question_id=q.id
);

INSERT INTO public.checklist_version_snapshots (organization_id, checklist_version_id, snapshot)
SELECT v.organization_id, v.id, '{}'::jsonb
FROM public.checklist_versions v
ON CONFLICT (checklist_version_id) DO NOTHING;

INSERT INTO public.checklist_schedules (organization_id, template_id, cron_expression)
SELECT t.organization_id, t.id, '0 9 * * *'
FROM public.checklist_templates t
WHERE NOT EXISTS (
  SELECT 1 FROM public.checklist_schedules s WHERE s.template_id=t.id
);

-- Sessions / tokens / idempotency
INSERT INTO public.user_sessions (id, organization_id, user_id, dpop_jkt, expires_at)
VALUES
  ('55555555-5555-4555-8555-555555555555','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','11111111-1111-4111-8111-111111111111','jkt-a', now()+interval '1 day'),
  ('55555555-5555-4555-8555-555555555556','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','22222222-2222-4222-8222-222222222222','jkt-b', now()+interval '1 day')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.user_session_tokens (id, organization_id, session_id, token_hash, sequence_number, expires_at)
VALUES
  ('66666666-6666-4666-8666-666666666666','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','55555555-5555-4555-8555-555555555555', repeat('a',64), 1, now()+interval '1 day'),
  ('66666666-6666-4666-8666-666666666667','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','55555555-5555-4555-8555-555555555556', repeat('b',64), 1, now()+interval '1 day')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.refresh_idempotency_records (
  id, organization_id, session_id, request_fingerprint, presented_token_hash, issued_token_id,
  response_ciphertext, response_iv, response_auth_tag, encryption_key_id, dpop_jkt, expires_at
) VALUES
  ('77777777-7777-4777-8777-777777777777','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','55555555-5555-4555-8555-555555555555',
   repeat('c',64), repeat('e',64), '66666666-6666-4666-8666-666666666666', '\x01','\x02','\x03','k1','jkt-a', now()+interval '30s'),
  ('77777777-7777-4777-8777-777777777778','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','55555555-5555-4555-8555-555555555556',
   repeat('d',64), repeat('f',64), '66666666-6666-4666-8666-666666666667', '\x01','\x02','\x03','k1','jkt-b', now()+interval '30s')
ON CONFLICT (id) DO NOTHING;

-- Cross-cutting security_events with org binding
INSERT INTO public.security_events (organization_id, category, severity, event_source, details)
VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','TEST','LOW','GATEWAY','{}'::jsonb),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','TEST','LOW','GATEWAY','{}'::jsonb);

INSERT INTO public.platform_admin_audit_logs (organization_id, admin_id, action, details)
SELECT 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', id, 'TEST', '{}'::jsonb
FROM public.platform_admins LIMIT 1;

-- Ensure at least one platform admin for audit logs
INSERT INTO public.platform_admins (id, email, display_name)
VALUES ('99999999-9999-4999-8999-999999999999','admin@example.com','Admin')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.platform_admin_audit_logs (organization_id, admin_id, action, details)
VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','99999999-9999-4999-8999-999999999999','TEST-A','{}'::jsonb),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','99999999-9999-4999-8999-999999999999','TEST-B','{}'::jsonb);

\echo NOTICE: seed_tenant_pairs OK
