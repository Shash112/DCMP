-- Phase 2.1.13 / 03 — refresh_idempotency_records (Correction A least privilege)
\set ON_ERROR_STOP on

CREATE TABLE IF NOT EXISTS public.refresh_idempotency_records (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         UUID NOT NULL,
  session_id              UUID NOT NULL,
  request_fingerprint     CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  presented_token_hash    CHAR(64) NOT NULL CHECK (presented_token_hash ~ '^[0-9a-f]{64}$'),
  issued_token_id         UUID NOT NULL,
  response_ciphertext     BYTEA NOT NULL,
  response_iv             BYTEA NOT NULL CHECK (octet_length(response_iv) = 12),
  response_auth_tag       BYTEA NOT NULL CHECK (octet_length(response_auth_tag) = 16),
  encryption_key_id       TEXT NOT NULL,
  dpop_jkt                TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at              TIMESTAMPTZ NOT NULL,
  invalidated_at          TIMESTAMPTZ NULL,
  CONSTRAINT uq_refresh_idempo_fingerprint
    UNIQUE (organization_id, session_id, request_fingerprint),
  CONSTRAINT fk_refresh_idempo_session
    FOREIGN KEY (organization_id, session_id)
    REFERENCES public.user_sessions (organization_id, id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_idempo_issued_token
    FOREIGN KEY (organization_id, session_id, issued_token_id)
    REFERENCES public.user_session_tokens (organization_id, session_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_idempo_org_id
  ON public.refresh_idempotency_records (organization_id, id);

CREATE INDEX IF NOT EXISTS ix_refresh_idempo_expiry
  ON public.refresh_idempotency_records (expires_at)
  WHERE invalidated_at IS NULL;

ALTER TABLE public.refresh_idempotency_records OWNER TO dcmp_migrator;

-- Prevent in-place mutation of security-sensitive columns after insert
CREATE OR REPLACE FUNCTION public.fn_refresh_idempo_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.session_id IS DISTINCT FROM OLD.session_id
       OR NEW.request_fingerprint IS DISTINCT FROM OLD.request_fingerprint
       OR NEW.presented_token_hash IS DISTINCT FROM OLD.presented_token_hash
       OR NEW.issued_token_id IS DISTINCT FROM OLD.issued_token_id
       OR NEW.response_ciphertext IS DISTINCT FROM OLD.response_ciphertext
       OR NEW.response_iv IS DISTINCT FROM OLD.response_iv
       OR NEW.response_auth_tag IS DISTINCT FROM OLD.response_auth_tag
       OR NEW.encryption_key_id IS DISTINCT FROM OLD.encryption_key_id
       OR NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: refresh idempotency security columns are immutable'
        USING ERRCODE = '42501';
    END IF;
    -- Only invalidated_at may change (NULL -> timestamp)
    IF OLD.invalidated_at IS NOT NULL AND NEW.invalidated_at IS DISTINCT FROM OLD.invalidated_at THEN
      RAISE EXCEPTION 'DCMP-SEC-42501: invalidated_at cannot be changed once set'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_refresh_idempo_immutable ON public.refresh_idempotency_records;
CREATE TRIGGER trg_refresh_idempo_immutable
  BEFORE UPDATE ON public.refresh_idempotency_records
  FOR EACH ROW EXECUTE FUNCTION public.fn_refresh_idempo_immutable();
