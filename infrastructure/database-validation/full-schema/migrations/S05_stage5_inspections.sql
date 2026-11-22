-- Phase 2.1.18 / S05 — Stage 5: inspection execution (5 entities)
\set ON_ERROR_STOP on

CREATE TABLE public.inspection_instances (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  assignment_id   UUID NOT NULL,
  version_id      UUID NOT NULL,
  attempt_number  INT NOT NULL CHECK (attempt_number > 0),
  inspector_id    UUID NOT NULL,
  status          TEXT NOT NULL DEFAULT 'IN_PROGRESS'
                    CHECK (status IN ('IN_PROGRESS','SUBMITTED','APPROVED','REJECTED','CANCELLED')),
  started_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at    TIMESTAMPTZ,
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, assignment_id, attempt_number),
  FOREIGN KEY (organization_id, assignment_id)
    REFERENCES public.checklist_assignments (organization_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (organization_id, version_id)
    REFERENCES public.checklist_versions (organization_id, id),
  FOREIGN KEY (organization_id, inspector_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.inspection_instances OWNER TO dcmp_migrator;

CREATE TABLE public.inspection_responses (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  inspection_id   UUID NOT NULL,
  question_id     UUID NOT NULL,
  answer          JSONB,
  answered_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (inspection_id, question_id),
  FOREIGN KEY (organization_id, inspection_id)
    REFERENCES public.inspection_instances (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, question_id)
    REFERENCES public.checklist_questions (organization_id, id)
);
ALTER TABLE public.inspection_responses OWNER TO dcmp_migrator;

CREATE TABLE public.inspection_evidence (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  UUID NOT NULL,
  inspection_id    UUID NOT NULL,
  response_id      UUID,
  uploaded_by      UUID NOT NULL,
  storage_bucket   TEXT NOT NULL,
  object_key       TEXT NOT NULL,
  content_type     TEXT,
  byte_size        BIGINT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (storage_bucket, object_key),
  FOREIGN KEY (organization_id, inspection_id)
    REFERENCES public.inspection_instances (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, response_id)
    REFERENCES public.inspection_responses (organization_id, id),
  FOREIGN KEY (organization_id, uploaded_by)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.inspection_evidence OWNER TO dcmp_migrator;

CREATE TABLE public.approval_records (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  inspection_id   UUID NOT NULL,
  approver_id     UUID NOT NULL,
  decision        TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
  comments        TEXT,
  decided_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, inspection_id)
    REFERENCES public.inspection_instances (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, approver_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.approval_records OWNER TO dcmp_migrator;

CREATE TABLE public.inspection_history (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  inspection_id   UUID NOT NULL,
  actor_id        UUID,
  event_type      TEXT NOT NULL,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, inspection_id)
    REFERENCES public.inspection_instances (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, actor_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.inspection_history OWNER TO dcmp_migrator;

\echo NOTICE: S05_stage5 OK (5 entities)
