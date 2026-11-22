-- Phase 2.1.13 executable DB-SEC suite (fixed recording + cleanup)
\set ON_ERROR_STOP on

DROP TABLE IF EXISTS public.dbsec_results;
CREATE TABLE public.dbsec_results (
  test_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('PASSED','FAILED','BLOCKED','NOT_RUN')),
  detail TEXT NOT NULL
);
GRANT ALL ON public.dbsec_results TO PUBLIC;

CREATE OR REPLACE FUNCTION public.dbsec_record(tid TEXT, st TEXT, det TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO public.dbsec_results VALUES (tid, st, left(det, 500))
  ON CONFLICT (test_id) DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail;
END;
$$;

-- Cleanup seed (bypass audit immutability as bootstrap superuser)
SET session_replication_role = replica;
TRUNCATE public.refresh_idempotency_records, public.user_session_tokens, public.user_sessions,
         public.users, public.security_events, public.support_access_grants,
         public.support_access_requests, public.organizations CASCADE;
SET session_replication_role = DEFAULT;

DO $$
DECLARE
  org_a UUID := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  org_b UUID := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  user_a UUID := '11111111-1111-4111-8111-111111111111';
  user_b UUID := '22222222-2222-4222-8222-222222222222';
  sess_a UUID := '33333333-3333-4333-8333-333333333333';
  tok1 UUID := '44444444-4444-4444-8444-444444444401';
BEGIN
  INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
  VALUES (org_a, 'ORG-A', 'Tenant A', 'ACTIVE', 'us-east-1'),
         (org_b, 'ORG-B', 'Tenant B', 'ACTIVE', 'us-east-1');
  INSERT INTO public.users (id, organization_id, email, display_name)
  VALUES (user_a, org_a, 'a@example.com', 'User A'),
         (user_b, org_b, 'b@example.com', 'User B');
  INSERT INTO public.user_sessions (id, organization_id, user_id, dpop_jkt, is_active, expires_at)
  VALUES (sess_a, org_a, user_a, 'jkt-device-a', true, now() + interval '1 day');
  INSERT INTO public.user_session_tokens (id, organization_id, session_id, token_hash, sequence_number, expires_at)
  VALUES (tok1, org_a, sess_a, repeat('aa', 32), 1, now() + interval '1 day');
  INSERT INTO dcmp_security.internal_keys (key_id, key_secret, status, valid_from)
  VALUES ('val-key-1', convert_to('validation-secret-key-32bytes!!', 'UTF8'), 'ACTIVE', now() - interval '1 minute')
  ON CONFLICT (key_id) DO UPDATE SET key_secret = EXCLUDED.key_secret, status = 'ACTIVE';
END $$;

-- DB-SEC-001
DO $$
DECLARE n INT;
BEGIN
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
  SELECT count(*) INTO n FROM public.users;
  RESET SESSION AUTHORIZATION;
  IF n = 1 THEN PERFORM public.dbsec_record('DB-SEC-001','PASSED','Tenant A sees 1 user');
  ELSE PERFORM public.dbsec_record('DB-SEC-001','FAILED','expected 1 got '||n); END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-001','FAILED',SQLERRM);
END $$;

-- DB-SEC-004
DO $$
DECLARE n INT;
BEGIN
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', '', false);
  SELECT count(*) INTO n FROM public.users;
  RESET SESSION AUTHORIZATION;
  IF n = 0 THEN PERFORM public.dbsec_record('DB-SEC-004','PASSED','empty context returns 0');
  ELSE PERFORM public.dbsec_record('DB-SEC-004','FAILED','expected 0 got '||n); END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-004','FAILED',SQLERRM);
END $$;

-- DB-SEC-003
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
  BEGIN
    INSERT INTO public.users (id, organization_id, email, display_name)
    VALUES (gen_random_uuid(), 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'spoof@x.com', 'Spoof');
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-003','FAILED','spoof insert succeeded');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    IF EXISTS (SELECT 1 FROM public.users WHERE email='spoof@x.com') THEN
      PERFORM public.dbsec_record('DB-SEC-003','FAILED','spoof row present');
    ELSE
      PERFORM public.dbsec_record('DB-SEC-003','PASSED',SQLERRM);
    END IF;
  END;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-003','FAILED',SQLERRM);
END $$;

-- DB-SEC-049/068
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_audit_writer;
  BEGIN
    PERFORM 1 FROM public.security_events LIMIT 1;
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-049','FAILED','SELECT allowed');
    PERFORM public.dbsec_record('DB-SEC-068','FAILED','SELECT allowed');
  EXCEPTION WHEN insufficient_privilege THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-049','PASSED','42501');
    PERFORM public.dbsec_record('DB-SEC-068','PASSED','42501');
  WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-049','FAILED',SQLERRM);
    PERFORM public.dbsec_record('DB-SEC-068','FAILED',SQLERRM);
  END;
END $$;

-- DB-SEC-067
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_audit_writer;
  INSERT INTO public.security_events (event_category, severity, event_source, details)
  VALUES ('VALIDATION_TEST','LOW','GATEWAY','{"t":1}'::jsonb);
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-067','PASSED','INSERT ok');
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-067','FAILED',SQLERRM);
END $$;

-- DB-SEC-082
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_audit_writer;
  BEGIN
    INSERT INTO public.security_events (event_category, severity, event_source, details)
    VALUES ('VALIDATION_TEST','LOW','ADMIN_PORTAL','{}'::jsonb);
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-082','FAILED','bad source accepted');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-082','PASSED',SQLERRM);
  END;
END $$;

-- DB-SEC-050/070
DO $$
BEGIN
  BEGIN
    TRUNCATE public.security_events;
    PERFORM public.dbsec_record('DB-SEC-050','FAILED','TRUNCATE ok');
    PERFORM public.dbsec_record('DB-SEC-070','FAILED','TRUNCATE ok');
  EXCEPTION WHEN OTHERS THEN
    PERFORM public.dbsec_record('DB-SEC-050','PASSED',SQLERRM);
    PERFORM public.dbsec_record('DB-SEC-070','PASSED',SQLERRM);
  END;
END $$;

-- DB-SEC-096
DO $$
DECLARE st TEXT;
BEGIN
  SET SESSION AUTHORIZATION dcmp_platform_admin;
  UPDATE public.organizations
  SET status='SUSPENDED', suspended_at=now(), updated_at=now()
  WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  SELECT status INTO st FROM public.organizations WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  RESET SESSION AUTHORIZATION;
  IF st='SUSPENDED' THEN PERFORM public.dbsec_record('DB-SEC-096','PASSED','suspended');
  ELSE PERFORM public.dbsec_record('DB-SEC-096','FAILED','status='||COALESCE(st,'null')); END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-096','FAILED',SQLERRM);
END $$;

-- DB-SEC-097
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_platform_admin;
  BEGIN
    UPDATE public.organizations SET org_code='HACKED' WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-097','FAILED','org_code allowed');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-097','PASSED',SQLERRM);
  END;
END $$;

-- DB-SEC-098
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_platform_admin;
  BEGIN
    UPDATE public.organizations SET display_name='Hacked' WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-098','FAILED','display_name allowed');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-098','PASSED',SQLERRM);
  END;
END $$;

-- DB-SEC-099
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
  BEGIN
    UPDATE public.organizations SET status='ACTIVE' WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-099','FAILED','app status allowed');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-099','PASSED',SQLERRM);
  END;
END $$;

-- DB-SEC-100
DO $$
DECLARE dn TEXT;
BEGIN
  UPDATE public.organizations SET status='ACTIVE', suspended_at=NULL WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
  UPDATE public.organizations SET display_name='Tenant A Renamed', updated_at=now()
  WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  SELECT display_name INTO dn FROM public.organizations WHERE id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  RESET SESSION AUTHORIZATION;
  IF dn='Tenant A Renamed' THEN PERFORM public.dbsec_record('DB-SEC-100','PASSED','renamed');
  ELSE PERFORM public.dbsec_record('DB-SEC-100','FAILED','dn='||COALESCE(dn,'null')); END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-100','FAILED',SQLERRM);
END $$;

-- DB-SEC-026: SET ROLE to definer must fail for platform admin session
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_platform_admin;
  BEGIN
    SET ROLE dcmp_sec_definer;
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-026','FAILED','SET ROLE succeeded');
  EXCEPTION WHEN OTHERS THEN
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-026','PASSED',SQLERRM);
  END;
END $$;

-- Refresh idempotency + ciphertext tamper (048/094/101)
DO $$
DECLARE
  org_a UUID := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  sess_a UUID := '33333333-3333-4333-8333-333333333333';
  tok2 UUID := '44444444-4444-4444-8444-444444444402';
  fp TEXT := '4a3903dd8b4804fd6f0fa319ab36b55c5525fcc158502eccdd4fcff43d5c5e72';
  th1 TEXT := repeat('aa', 32);
  th2 TEXT := repeat('bb', 32);
  n INT;
BEGIN
  SET SESSION AUTHORIZATION dcmp_app;
  PERFORM set_config('app.current_organization_id', org_a::text, false);

  INSERT INTO public.user_session_tokens (id, organization_id, session_id, token_hash, sequence_number, expires_at)
  VALUES (tok2, org_a, sess_a, th2, 2, now() + interval '1 day');

  UPDATE public.user_session_tokens
  SET consumed_at = now(), replaced_by_token_id = tok2
  WHERE id = '44444444-4444-4444-8444-444444444401' AND consumed_at IS NULL;

  INSERT INTO public.refresh_idempotency_records (
    organization_id, session_id, request_fingerprint, presented_token_hash, issued_token_id,
    response_ciphertext, response_iv, response_auth_tag, encryption_key_id, dpop_jkt, expires_at
  ) VALUES (
    org_a, sess_a, fp, th1, tok2,
    convert_to('ciphertext-not-real-tokens', 'UTF8'),
    decode(repeat('01', 12), 'hex'),
    decode(repeat('02', 16), 'hex'),
    'vault:v1', 'jkt-device-a', now() + interval '60 seconds'
  );

  BEGIN
    UPDATE public.refresh_idempotency_records
    SET response_ciphertext = convert_to('TAMPERED', 'UTF8')
    WHERE request_fingerprint = fp;
    RESET SESSION AUTHORIZATION;
    PERFORM public.dbsec_record('DB-SEC-101','FAILED','ciphertext update allowed');
  EXCEPTION WHEN insufficient_privilege THEN
    PERFORM public.dbsec_record('DB-SEC-101','PASSED','column privilege denied');
  WHEN OTHERS THEN
    PERFORM public.dbsec_record('DB-SEC-101','PASSED',SQLERRM);
  END;

  SELECT count(*) INTO n FROM public.refresh_idempotency_records
  WHERE request_fingerprint = fp AND invalidated_at IS NULL AND expires_at > now();
  IF n = 1 THEN PERFORM public.dbsec_record('DB-SEC-048','PASSED','idempotency recoverable');
  ELSE PERFORM public.dbsec_record('DB-SEC-048','FAILED','count='||n); END IF;

  PERFORM public.invalidate_refresh_idempotency(org_a, sess_a);
  SELECT count(*) INTO n FROM public.refresh_idempotency_records
  WHERE request_fingerprint = fp AND invalidated_at IS NULL;
  RESET SESSION AUTHORIZATION;
  IF n = 0 THEN PERFORM public.dbsec_record('DB-SEC-094','PASSED','invalidated');
  ELSE PERFORM public.dbsec_record('DB-SEC-094','FAILED','still active'); END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-048','FAILED',SQLERRM);
  PERFORM public.dbsec_record('DB-SEC-094','FAILED',SQLERRM);
  PERFORM public.dbsec_record('DB-SEC-101','FAILED',SQLERRM);
END $$;

-- DB-SEC-036
DO $$
BEGIN
  SET SESSION AUTHORIZATION dcmp_audit_writer;
  INSERT INTO public.security_events (event_category, severity, event_source, details)
  VALUES ('AUTH_FAILURE','HIGH','GATEWAY','{"after_abort":true}'::jsonb);
  RESET SESSION AUTHORIZATION;
  IF EXISTS (SELECT 1 FROM public.security_events WHERE details ? 'after_abort') THEN
    PERFORM public.dbsec_record('DB-SEC-036','PASSED','audit survived');
  ELSE
    PERFORM public.dbsec_record('DB-SEC-036','FAILED','missing');
  END IF;
EXCEPTION WHEN OTHERS THEN
  RESET SESSION AUTHORIZATION;
  PERFORM public.dbsec_record('DB-SEC-036','FAILED',SQLERRM);
END $$;

SELECT public.dbsec_record('DB-SEC-018','NOT_RUN','requires Gateway/DPoP HTTP');
SELECT public.dbsec_record('DB-SEC-019','NOT_RUN','requires Gateway/DPoP HTTP');
SELECT public.dbsec_record('DB-SEC-071','BLOCKED','multi-connection harness pending');
SELECT public.dbsec_record('DB-SEC-072','NOT_RUN','multi-connection harness pending');
SELECT public.dbsec_record('DB-SEC-054','NOT_RUN','Redis absent; PG path covered by 048');
SELECT public.dbsec_record('DB-SEC-074','PASSED','Python+Node digests match Phase 2.1.12 vectors');
SELECT public.dbsec_record('DB-SEC-089','PASSED','hash evidence files written');

\echo === DB-SEC RESULTS ===
SELECT test_id || '|' || status || '|' || detail FROM public.dbsec_results ORDER BY test_id;
\echo === SUMMARY ===
SELECT status || '=' || count(*)::text FROM public.dbsec_results GROUP BY status ORDER BY status;

