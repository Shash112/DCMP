-- Phase 2.1.18 / S06 — Stage 6: issues, CAPA, sync (5 entities)
\set ON_ERROR_STOP on

CREATE TABLE public.issues (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  inspection_id   UUID,
  response_id     UUID,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status          TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED','CLOSED','CANCELLED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, inspection_id)
    REFERENCES public.inspection_instances (organization_id, id),
  FOREIGN KEY (organization_id, response_id)
    REFERENCES public.inspection_responses (organization_id, id)
);
ALTER TABLE public.issues OWNER TO dcmp_migrator;

CREATE TABLE public.corrective_actions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  issue_id        UUID NOT NULL,
  assignee_id     UUID,
  title           TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN','IN_PROGRESS','DONE','CANCELLED')),
  due_at          TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, issue_id)
    REFERENCES public.issues (organization_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (organization_id, assignee_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.corrective_actions OWNER TO dcmp_migrator;

CREATE TABLE public.corrective_action_history (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  action_id       UUID NOT NULL,
  actor_id        UUID,
  event_type      TEXT NOT NULL,
  details         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, action_id)
    REFERENCES public.corrective_actions (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, actor_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.corrective_action_history OWNER TO dcmp_migrator;

CREATE TABLE public.sync_operations (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     UUID NOT NULL,
  device_id           UUID NOT NULL,
  user_id             UUID NOT NULL,
  client_operation_id TEXT NOT NULL,
  operation_type      TEXT NOT NULL,
  payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
  status              TEXT NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING','APPLIED','REJECTED','CONFLICT')),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, client_operation_id),
  FOREIGN KEY (organization_id, device_id)
    REFERENCES public.mobile_devices (organization_id, id),
  FOREIGN KEY (organization_id, user_id)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.sync_operations OWNER TO dcmp_migrator;

CREATE TABLE public.sync_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  operation_id    UUID,
  device_id       UUID NOT NULL,
  level           TEXT NOT NULL DEFAULT 'INFO',
  message         TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, operation_id)
    REFERENCES public.sync_operations (organization_id, id),
  FOREIGN KEY (organization_id, device_id)
    REFERENCES public.mobile_devices (organization_id, id)
);
ALTER TABLE public.sync_logs OWNER TO dcmp_migrator;

\echo NOTICE: S06_stage6 OK (5 entities)
