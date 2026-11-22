-- Phase 2.1.13 / 06 — SECURITY DEFINER helpers + support session functions
\set ON_ERROR_STOP on

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
  v_jti UUID;
  v_iat TIMESTAMPTZ;
  v_exp TIMESTAMPTZ;
  v_req_status TEXT;
  v_req_admin UUID;
  v_req_org UUID;
  v_txid BIGINT;
  v_sig TEXT;
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
  -- Normalize base64url comparison via sha256 digests of strings
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
  v_jti := (v_claims->>'jti')::uuid;
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
    AND platform_admin_id = v_sub
    AND organization_id = p_org_id
    AND grant_id = p_grant_id
    AND consumed_at IS NULL
    AND expires_at > v_now;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DCMP-SEC-28019: Challenge invalid' USING ERRCODE = '28000';
  END IF;

  SELECT status, platform_admin_id, organization_id
  INTO v_req_status, v_req_admin, v_req_org
  FROM public.support_access_requests WHERE id = v_req_id;
  IF NOT FOUND OR v_req_status <> 'APPROVED' OR v_req_admin <> v_sub OR v_req_org <> p_org_id THEN
    RAISE EXCEPTION 'DCMP-SEC-28020: Request invalid' USING ERRCODE = '28000';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.support_access_grants g
    WHERE g.id = p_grant_id AND g.request_id = v_req_id AND g.organization_id = p_org_id
      AND g.revoked_at IS NULL AND g.expires_at > statement_timestamp()
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

-- Controlled invalidation (Correction A): SECURITY INVOKER so FORCE RLS +
-- column grant UPDATE(invalidated_at) to dcmp_app apply. Do not use a
-- migrator SECURITY DEFINER here — FORCE RLS would hide all rows without a policy.
CREATE OR REPLACE FUNCTION public.invalidate_refresh_idempotency(p_org UUID, p_session UUID)
RETURNS INT
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  n INT;
BEGIN
  UPDATE public.refresh_idempotency_records
  SET invalidated_at = clock_timestamp()
  WHERE organization_id = p_org
    AND session_id = p_session
    AND invalidated_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;
ALTER FUNCTION public.invalidate_refresh_idempotency(UUID, UUID) OWNER TO dcmp_migrator;
