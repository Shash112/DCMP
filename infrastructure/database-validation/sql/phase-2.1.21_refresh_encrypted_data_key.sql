-- Phase 2.1.21 — store KMS-wrapped DEK alongside AES-GCM ciphertext (nullable for local mode)
\set ON_ERROR_STOP on

ALTER TABLE public.refresh_idempotency_records
  ADD COLUMN IF NOT EXISTS encrypted_data_key bytea;

COMMENT ON COLUMN public.refresh_idempotency_records.encrypted_data_key IS
  'KMS CiphertextBlob for AES-256 DEK; NULL when using local long-lived test keys';

\echo NOTICE: phase-2.1.21 refresh encrypted_data_key column OK
