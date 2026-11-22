-- Phase 2.1.18 / S04 — Stage 4: schedules & assignments (3 entities)
\set ON_ERROR_STOP on

CREATE TABLE public.checklist_schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  template_id     UUID NOT NULL,
  cron_expression TEXT,
  timezone        TEXT NOT NULL DEFAULT 'UTC',
  is_active       BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, template_id)
    REFERENCES public.checklist_templates (organization_id, id)
);
ALTER TABLE public.checklist_schedules OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_assignments (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  schedule_id     UUID,
  version_id      UUID NOT NULL,
  assigned_by     UUID,
  due_at          TIMESTAMPTZ,
  status          TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN','IN_PROGRESS','COMPLETED','CANCELLED','OVERDUE')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, schedule_id)
    REFERENCES public.checklist_schedules (organization_id, id),
  FOREIGN KEY (organization_id, version_id)
    REFERENCES public.checklist_versions (organization_id, id),
  FOREIGN KEY (organization_id, assigned_by)
    REFERENCES public.users (organization_id, id)
);
ALTER TABLE public.checklist_assignments OWNER TO dcmp_migrator;

CREATE TABLE public.assignment_targets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  assignment_id   UUID NOT NULL,
  target_type     TEXT NOT NULL CHECK (target_type IN ('USER','TEAM','LOCATION')),
  user_id         UUID,
  team_id         UUID,
  location_id     UUID,
  CHECK (
    (target_type = 'USER' AND user_id IS NOT NULL AND team_id IS NULL AND location_id IS NULL)
    OR (target_type = 'TEAM' AND team_id IS NOT NULL AND user_id IS NULL AND location_id IS NULL)
    OR (target_type = 'LOCATION' AND location_id IS NOT NULL AND user_id IS NULL AND team_id IS NULL)
  ),
  FOREIGN KEY (organization_id, assignment_id)
    REFERENCES public.checklist_assignments (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, user_id) REFERENCES public.users (organization_id, id),
  FOREIGN KEY (organization_id, team_id) REFERENCES public.teams (organization_id, id),
  FOREIGN KEY (organization_id, location_id) REFERENCES public.locations (organization_id, id)
);
ALTER TABLE public.assignment_targets OWNER TO dcmp_migrator;

\echo NOTICE: S04_stage4 OK (3 entities)
