-- Phase 2.1.21 — open_support_session_attested
-- Used when gateway has already VerifyMac'd via non-exportable KMS HMAC.
-- Still enforces JTI, challenge, grant, org, temporal claims. NOT a platform-admin bypass.
\set ON_ERROR_STOP on

CREATE OR REPLACE FUNCTION dcmp_security.open_support_session_attested(
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
  v_attested TEXT;
BEGIN
  v_attested := nullif(current_setting('app.ssa_kms_attested', true), '');
  IF v_attested IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'DCMP-SEC-28030: KMS attestation GUC required' USING ERRCODE = '28000';
  END IF;

  v_parts := string_to_array(p_assertion_jwt, '.');
  IF array_length(v_parts, 1) <> 3 THEN
    RAISE EXCEPTION 'DCMP-SEC-28001: Malformed JWT' USING ERRCODE = '28000';
  END IF;
  BEGIN
    v_header := convert_from(dcmp_security.b64url_to_bytea(v_parts[1]), 'utf8')::jsonb;
    v_claims := convert_from(dcmp_security.b64url_to_bytea(v_parts[2]), 'utf8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'DCMP-SEC-28002: Base64 decode failed' USING ERRCODE = '28000';
  END;

  IF (v_header->>'alg') IS DISTINCT FROM 'HS256' OR (v_header->>'typ') IS DISTINCT FROM 'JWT' THEN
    RAISE EXCEPTION 'DCMP-SEC-28003: Invalid alg/typ' USING ERRCODE = '28000';
  END IF;

  -- Signature authenticity is attested by gateway KMS VerifyMac (GUC).
  -- Still bind claims tightly.
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

  -- Session signature still derived from a local verification secret when present;
  -- for KMS mode use a deterministic attestation marker (not a platform bypass).
  v_sig := encode(
    digest(
      ('kms-attested|v1|' || p_org_id::text || '|' || p_grant_id::text || '|' || v_sub::text || '|' || p_challenge_id::text || '|' || v_txid::text)::bytea,
      'sha256'
    ),
    'hex'
  );
  PERFORM set_config('app.current_organization_id', p_org_id::text, true);
  PERFORM set_config('app.active_support_grant_id', p_grant_id::text, true);
  PERFORM set_config('app.authenticated_admin_id', v_sub::text, true);
  PERFORM set_config('app.support_challenge_id', p_challenge_id::text, true);
  PERFORM set_config('app.support_signature', v_sig, true);
  PERFORM set_config('app.ssa_kms_attested', 'false', true);
END;
$$;

ALTER FUNCTION dcmp_security.open_support_session_attested(TEXT, UUID, UUID, UUID) OWNER TO dcmp_sec_definer;
REVOKE ALL ON FUNCTION dcmp_security.open_support_session_attested(TEXT, UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dcmp_security.open_support_session_attested(TEXT, UUID, UUID, UUID) TO dcmp_platform_admin;

\echo NOTICE: phase-2.1.21 SSA KMS attested open OK
