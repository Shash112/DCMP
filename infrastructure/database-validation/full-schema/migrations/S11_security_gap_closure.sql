-- Phase 2.1.19 / S11 — Security gap closure on full schema (additive; does not drop 63 entities)
-- Reconciles Stage 1 security subset features into dcmp_full_schema_validation.
\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

----------------------------------------------------------------------------
-- A1. security_events: event_source, recorded_by, immutability, TRUNCATE guard
----------------------------------------------------------------------------
ALTER TABLE public.security_events
  ADD COLUMN IF NOT EXISTS event_source TEXT,
  ADD COLUMN IF NOT EXISTS recorded_by TEXT,
  ADD COLUMN IF NOT EXISTS actor_id UUID,
  ADD COLUMN IF NOT EXISTS correlation_id UUID;

UPDATE public.security_events
   SET event_source = COALESCE(event_source, 'GATEWAY'),
       recorded_by = COALESCE(recorded_by, 'dcmp_migrator')
 WHERE event_source IS NULL OR recorded_by IS NULL;

ALTER TABLE public.security_events
  ALTER COLUMN event_source SET DEFAULT 'GATEWAY',
  ALTER COLUMN event_source SET NOT NULL,
  ALTER COLUMN recorded_by SET DEFAULT CURRENT_USER,
  ALTER COLUMN recorded_by SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'security_events_event_source_check'
      AND conrelid = 'public.security_events'::regclass
  ) THEN
    ALTER TABLE public.security_events
      ADD CONSTRAINT security_events_event_source_check
      CHECK (event_source IN ('GATEWAY','AUTH_SERVICE','DATABASE_TRIGGER','ADMIN_PORTAL'));
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.fn_prevent_audit_dml()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit UPDATE/DELETE prohibited' USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION public.fn_prevent_audit_truncate()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'DCMP-SEC-42501: Audit TRUNCATE prohibited' USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION public.fn_security_events_before_insert()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
  NEW.id := COALESCE(NEW.id, gen_random_uuid());
  NEW.created_at := clock_timestamp();
  NEW.recorded_by := CURRENT_USER;
  IF CURRENT_USER = 'dcmp_audit_writer' AND NEW.event_source IS DISTINCT FROM 'GATEWAY' THEN
    RAISE EXCEPTION 'DCMP-SEC-42501: invalid event_source for audit writer' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_security_events_dml ON public.security_events;
CREATE TRIGGER trg_protect_security_events_dml
  BEFORE UPDATE OR DELETE ON public.security_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_prevent_audit_dml();

DROP TRIGGER IF EXISTS trg_protect_security_events_truncate ON public.security_events;
CREATE TRIGGER trg_protect_security_events_truncate
  BEFORE TRUNCATE ON public.security_events
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_prevent_audit_truncate();

DROP TRIGGER IF EXISTS trg_security_events_before_insert ON public.security_events;
CREATE TRIGGER trg_security_events_before_insert
  BEFORE INSERT ON public.security_events
  FOR EACH ROW EXECUTE FUNCTION public.fn_security_events_before_insert();

DROP POLICY IF EXISTS audit_sec_ins ON public.security_events;
CREATE POLICY audit_sec_ins ON public.security_events
  AS PERMISSIVE FOR INSERT TO dcmp_audit_writer
  WITH CHECK (recorded_by = CURRENT_USER AND event_source = 'GATEWAY');

REVOKE ALL ON public.security_events FROM dcmp_audit_writer;
GRANT INSERT (id, organization_id, category, severity, details, event_source, actor_id, correlation_id, recorded_by, created_at)
  ON public.security_events TO dcmp_audit_writer;

----------------------------------------------------------------------------
-- A2. Harden dcmp_security.internal_keys for SSA HMAC
----------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='dcmp_security' AND table_name='internal_keys' AND column_name='key_material'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='dcmp_security' AND table_name='internal_keys' AND column_name='key_secret'
  ) THEN
    ALTER TABLE dcmp_security.internal_keys RENAME COLUMN key_material TO key_secret;
  END IF;
END $$;

ALTER TABLE dcmp_security.internal_keys
  ADD COLUMN IF NOT EXISTS status TEXT,
  ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ;

UPDATE dcmp_security.internal_keys
   SET status = COALESCE(status, 'ACTIVE'),
       valid_from = COALESCE(valid_from, created_at, clock_timestamp())
 WHERE status IS NULL OR valid_from IS NULL;

ALTER TABLE dcmp_security.internal_keys
  ALTER COLUMN status SET NOT NULL,
  ALTER COLUMN valid_from SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'internal_keys_status_check'
      AND conrelid = 'dcmp_security.internal_keys'::regclass
  ) THEN
    ALTER TABLE dcmp_security.internal_keys
      ADD CONSTRAINT internal_keys_status_check
      CHECK (status IN ('ACTIVE','RETIRED','REVOKED'));
  END IF;
END $$;

----------------------------------------------------------------------------
-- A3. Evolve support_session_challenges for SSA
----------------------------------------------------------------------------
ALTER TABLE dcmp_security.support_session_challenges
  ADD COLUMN IF NOT EXISTS organization_id UUID,
  ADD COLUMN IF NOT EXISTS transaction_xid BIGINT,
  ADD COLUMN IF NOT EXISTS platform_admin_id UUID,
  ADD COLUMN IF NOT EXISTS challenge_id UUID;

UPDATE dcmp_security.support_session_challenges
   SET platform_admin_id = COALESCE(platform_admin_id, admin_id),
       challenge_id = COALESCE(challenge_id, id)
 WHERE platform_admin_id IS NULL OR challenge_id IS NULL;

-- Keep id as PK; challenge_id unique for SSA lookups
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'support_session_challenges_challenge_id_key'
      AND conrelid = 'dcmp_security.support_session_challenges'::regclass
  ) THEN
    ALTER TABLE dcmp_security.support_session_challenges
      ADD CONSTRAINT support_session_challenges_challenge_id_key UNIQUE (challenge_id);
  END IF;
END $$;

----------------------------------------------------------------------------
-- A4. Align support request/grant status for SSA (additive columns/checks)
----------------------------------------------------------------------------
ALTER TABLE public.support_access_requests
  ADD COLUMN IF NOT EXISTS platform_admin_id UUID;

UPDATE public.support_access_requests
   SET platform_admin_id = COALESCE(platform_admin_id, admin_id)
 WHERE platform_admin_id IS NULL;

ALTER TABLE public.support_access_grants
  ADD COLUMN IF NOT EXISTS request_id UUID;

UPDATE public.support_access_grants
   SET request_id = COALESCE(request_id, support_access_request_id)
 WHERE request_id IS NULL;

----------------------------------------------------------------------------
-- A5. SSA SECURITY DEFINER functions (adapted to full-schema column names)
----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION dcmp_security.constant_time_eq(a BYTEA, b BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dcmp_security, public, pg_temp
AS $$
DECLARE
  i INT;
  acc INT := 0;
BEGIN
  IF a IS NULL OR b IS NULL OR octet_length(a) <> 32 OR octet_length(b) <> 32 THEN
    RETURN false;
  END IF;
  FOR i IN 0..31 LOOP
    acc := acc | (get_byte(a, i) # get_byte(b, i));
  END LOOP;
  RETURN acc = 0;
END;
$$;
ALTER FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.constant_time_eq(BYTEA, BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION dcmp_security.verify_support_signature()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, dcmp_security, public, pg_temp
AS $$
DECLARE
  v_org_id TEXT;
  v_grant_id TEXT;
  v_admin_id TEXT;
  v_challenge_id TEXT;
  v_sig_hex TEXT;
  v_secret BYTEA;
  v_expected TEXT;
  v_active BOOLEAN;
BEGIN
  v_org_id := NULLIF(current_setting('app.current_organization_id', true), '');
  v_grant_id := NULLIF(current_setting('app.active_support_grant_id', true), '');
  v_admin_id := NULLIF(current_setting('app.authenticated_admin_id', true), '');
  v_challenge_id := NULLIF(current_setting('app.support_challenge_id', true), '');
  v_sig_hex := NULLIF(current_setting('app.support_signature', true), '');
  IF v_org_id IS NULL OR v_grant_id IS NULL OR v_admin_id IS NULL OR v_challenge_id IS NULL OR v_sig_hex IS NULL THEN
    RETURN false;
  END IF;

  SELECT key_secret INTO v_secret
  FROM dcmp_security.internal_keys
  WHERE status = 'ACTIVE'
    AND clock_timestamp() >= valid_from
    AND (valid_until IS NULL OR clock_timestamp() < valid_until)
  ORDER BY valid_from DESC LIMIT 1;
  IF v_secret IS NULL THEN
    RETURN false;
  END IF;

  v_expected := encode(
    hmac(
      ('v1|' || v_org_id || '|' || v_grant_id || '|' || v_admin_id || '|' || v_challenge_id || '|' || txid_current()::text)::bytea,
      v_secret,
      'sha256'
    ),
    'hex'
  );
  IF NOT dcmp_security.constant_time_eq(digest(v_sig_hex, 'sha256'), digest(v_expected, 'sha256')) THEN
    RETURN false;
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM public.support_access_grants g
    WHERE g.id = v_grant_id::uuid
      AND g.organization_id = v_org_id::uuid
      AND g.revoked_at IS NULL
      AND g.expires_at > statement_timestamp()
  ) INTO v_active;
  RETURN v_active;
END;
$$;
ALTER FUNCTION dcmp_security.verify_support_signature() OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.verify_support_signature() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.verify_support_signature() TO dcmp_platform_admin;

CREATE OR REPLACE FUNCTION dcmp_security.open_support_session(
  p_assertion_jwt TEXT,
  p_org_id UUID,
  p_grant_id UUID,
  p_challenge_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, dcmp_security, public, pg_temp
AS $$
DECLARE
  v_parts TEXT[];
  v_header JSONB;
  v_claims JSONB;
  v_kid TEXT;
  v_secret BYTEA;
  v_key_status TEXT;
  v_valid_from TIMESTAMPTZ;
  v_valid_until TIMESTAMPTZ;
  v_expected TEXT;
  v_now TIMESTAMPTZ := clock_timestamp();
  v_sub UUID;
  v_req_id UUID;
  v_jti TEXT;
  v_iat TIMESTAMPTZ;
  v_exp TIMESTAMPTZ;
  v_req_status TEXT;
  v_req_admin UUID;
  v_req_org UUID;
  v_txid BIGINT;
  v_sig TEXT;
  v_updated INT;
BEGIN
  v_parts := string_to_array(p_assertion_jwt, '.');
  IF array_length(v_parts, 1) <> 3 THEN
    RAISE EXCEPTION 'DCMP-SEC-28001: Malformed JWT' USING ERRCODE = '28000';
  END IF;
  BEGIN
    v_header := convert_from(decode(replace(replace(v_parts[1], '-', '+'), '_', '/'), 'base64'), 'utf8')::jsonb;
    v_claims := convert_from(decode(replace(replace(v_parts[2], '-', '+'), '_', '/'), 'base64'), 'utf8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'DCMP-SEC-28002: Base64 decode failed' USING ERRCODE = '28000';
  END;

  IF (v_header->>'alg') IS DISTINCT FROM 'HS256' OR (v_header->>'typ') IS DISTINCT FROM 'JWT' THEN
    RAISE EXCEPTION 'DCMP-SEC-28003: Invalid alg/typ' USING ERRCODE = '28000';
  END IF;
  v_kid := v_header->>'kid';

  SELECT key_secret, status, valid_from, valid_until
  INTO v_secret, v_key_status, v_valid_from, v_valid_until
  FROM dcmp_security.internal_keys WHERE key_id = v_kid;
  IF NOT FOUND OR v_key_status <> 'ACTIVE' OR v_now < v_valid_from
     OR (v_valid_until IS NOT NULL AND v_now >= v_valid_until) THEN
    RAISE EXCEPTION 'DCMP-SEC-28006: Key invalid' USING ERRCODE = '28000';
  END IF;

  v_expected := encode(
    hmac((v_parts[1] || '.' || v_parts[2])::bytea, v_secret, 'sha256'),
    'base64'
  );
  IF NOT dcmp_security.constant_time_eq(
       digest(replace(replace(rtrim(v_expected, '='), '+', '-'), '/', '_'), 'sha256'),
       digest(v_parts[3], 'sha256')
     ) THEN
    RAISE EXCEPTION 'DCMP-SEC-28009: Signature mismatch' USING ERRCODE = '28000';
  END IF;

  IF (v_claims->>'iss') IS DISTINCT FROM 'dcmp-platform-gateway'
     OR (v_claims->>'aud') IS DISTINCT FROM 'dcmp-database-engine' THEN
    RAISE EXCEPTION 'DCMP-SEC-28010: Invalid iss/aud' USING ERRCODE = '28000';
  END IF;

  v_sub := (v_claims->>'sub')::uuid;
  v_req_id := (v_claims->>'req_id')::uuid;
  v_jti := (v_claims->>'jti');
  v_iat := to_timestamp((v_claims->>'iat')::double precision);
  v_exp := to_timestamp((v_claims->>'exp')::double precision);

  IF (v_claims->>'org_id')::uuid IS DISTINCT FROM p_org_id
     OR (v_claims->>'grant_id')::uuid IS DISTINCT FROM p_grant_id THEN
    RAISE EXCEPTION 'DCMP-SEC-28012: Org/grant mismatch' USING ERRCODE = '28000';
  END IF;
  IF v_exp <= v_iat OR v_iat > (v_now + INTERVAL '60s') OR v_exp <= (v_now - INTERVAL '5s')
     OR (v_exp - v_iat) > INTERVAL '15m' THEN
    RAISE EXCEPTION 'DCMP-SEC-28014: Temporal violation' USING ERRCODE = '28000';
  END IF;

  BEGIN
    INSERT INTO dcmp_security.consumed_support_assertions (jti, admin_id, grant_id, consumed_at, expires_at)
    VALUES (v_jti, v_sub, p_grant_id, v_now, v_exp);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'DCMP-SEC-28018: JTI consumed' USING ERRCODE = '23505';
  END;

  v_txid := txid_current();
  UPDATE dcmp_security.support_session_challenges
  SET consumed_at = v_now, transaction_xid = v_txid
  WHERE challenge_id = p_challenge_id
    AND COALESCE(platform_admin_id, admin_id) = v_sub
    AND organization_id = p_org_id
    AND grant_id = p_grant_id
    AND consumed_at IS NULL
    AND expires_at > v_now;
  GET DIAGNOSTICS v_updated = ROW_COUNT;
  IF v_updated = 0 THEN
    RAISE EXCEPTION 'DCMP-SEC-28019: Challenge invalid' USING ERRCODE = '28000';
  END IF;

  SELECT status, COALESCE(platform_admin_id, admin_id), organization_id
  INTO v_req_status, v_req_admin, v_req_org
  FROM public.support_access_requests WHERE id = v_req_id;
  IF NOT FOUND OR v_req_status <> 'APPROVED' OR v_req_admin <> v_sub OR v_req_org <> p_org_id THEN
    RAISE EXCEPTION 'DCMP-SEC-28020: Request invalid' USING ERRCODE = '28000';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.support_access_grants g
    WHERE g.id = p_grant_id
      AND COALESCE(g.request_id, g.support_access_request_id) = v_req_id
      AND g.organization_id = p_org_id
      AND g.revoked_at IS NULL
      AND g.expires_at > statement_timestamp()
  ) THEN
    RAISE EXCEPTION 'DCMP-SEC-28023: Grant inactive' USING ERRCODE = '28000';
  END IF;

  v_sig := encode(
    hmac(
      ('v1|' || p_org_id::text || '|' || p_grant_id::text || '|' || v_sub::text || '|' || p_challenge_id::text || '|' || v_txid::text)::bytea,
      v_secret,
      'sha256'
    ),
    'hex'
  );
  PERFORM set_config('app.current_organization_id', p_org_id::text, true);
  PERFORM set_config('app.active_support_grant_id', p_grant_id::text, true);
  PERFORM set_config('app.authenticated_admin_id', v_sub::text, true);
  PERFORM set_config('app.support_challenge_id', p_challenge_id::text, true);
  PERFORM set_config('app.support_signature', v_sig, true);
END;
$$;
ALTER FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session(TEXT, UUID, UUID, UUID) TO dcmp_platform_admin;

GRANT SELECT ON public.support_access_grants TO dcmp_sec_definer;
GRANT SELECT ON public.support_access_requests TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.internal_keys TO dcmp_sec_definer;
GRANT SELECT, INSERT ON dcmp_security.consumed_support_assertions TO dcmp_sec_definer;
GRANT SELECT, INSERT, UPDATE ON dcmp_security.support_session_challenges TO dcmp_sec_definer;

----------------------------------------------------------------------------
-- A6. Platform-admin support-session RLS (not a general bypass)
----------------------------------------------------------------------------
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
    EXECUTE format('GRANT SELECT ON public.%I TO dcmp_platform_admin', t);
    EXECUTE format('DROP POLICY IF EXISTS padmin_%I_p ON public.%I', t, t);
    EXECUTE format('DROP POLICY IF EXISTS padmin_%I_r ON public.%I', t, t);
    EXECUTE format(
      'CREATE POLICY padmin_%I_p ON public.%I AS PERMISSIVE FOR SELECT TO dcmp_platform_admin
         USING (dcmp_security.verify_support_signature())', t, t);
    EXECUTE format(
      'CREATE POLICY padmin_%I_r ON public.%I AS RESTRICTIVE FOR SELECT TO dcmp_platform_admin
         USING (organization_id = NULLIF(current_setting(''app.current_organization_id'', true), '''')::uuid)',
      t, t);
  END LOOP;
END $$;

\echo NOTICE: S11_security_gap_closure OK
