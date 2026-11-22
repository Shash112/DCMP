-- Phase 2.1.18 / S03 — Stage 3: checklist templates (8 entities)
\set ON_ERROR_STOP on

CREATE TABLE public.checklist_categories (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  name            TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, name)
);
ALTER TABLE public.checklist_categories OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_templates (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id),
  category_id     UUID,
  code            TEXT NOT NULL,
  name            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'DRAFT'
                    CHECK (status IN ('DRAFT','PUBLISHED','ARCHIVED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, code),
  FOREIGN KEY (organization_id, category_id)
    REFERENCES public.checklist_categories (organization_id, id)
);
ALTER TABLE public.checklist_templates OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_versions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  template_id     UUID NOT NULL,
  version_number  INT NOT NULL CHECK (version_number > 0),
  status          TEXT NOT NULL DEFAULT 'DRAFT'
                    CHECK (status IN ('DRAFT','PUBLISHED','SUPERSEDED')),
  published_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id),
  UNIQUE (template_id, version_number),
  FOREIGN KEY (organization_id, template_id)
    REFERENCES public.checklist_templates (organization_id, id)
);
ALTER TABLE public.checklist_versions OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_sections (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  version_id      UUID NOT NULL,
  title           TEXT NOT NULL,
  sort_order      INT NOT NULL DEFAULT 0,
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, version_id)
    REFERENCES public.checklist_versions (organization_id, id)
);
ALTER TABLE public.checklist_sections OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_questions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  version_id      UUID NOT NULL,
  section_id      UUID NOT NULL,
  question_key    TEXT NOT NULL,
  prompt          TEXT NOT NULL,
  question_type   TEXT NOT NULL
                    CHECK (question_type IN ('TEXT','NUMBER','BOOLEAN','SINGLE_SELECT','MULTI_SELECT','PHOTO','SIGNATURE')),
  is_required     BOOLEAN NOT NULL DEFAULT false,
  sort_order      INT NOT NULL DEFAULT 0,
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, version_id, id),
  UNIQUE (section_id, question_key),
  FOREIGN KEY (organization_id, version_id)
    REFERENCES public.checklist_versions (organization_id, id),
  FOREIGN KEY (organization_id, section_id)
    REFERENCES public.checklist_sections (organization_id, id)
);
ALTER TABLE public.checklist_questions OWNER TO dcmp_migrator;

CREATE TABLE public.question_options (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL,
  question_id     UUID NOT NULL,
  option_key      TEXT NOT NULL,
  label           TEXT NOT NULL,
  sort_order      INT NOT NULL DEFAULT 0,
  UNIQUE (organization_id, id),
  UNIQUE (question_id, option_key),
  FOREIGN KEY (organization_id, question_id)
    REFERENCES public.checklist_questions (organization_id, id)
);
ALTER TABLE public.question_options OWNER TO dcmp_migrator;

CREATE TABLE public.question_conditions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    UUID NOT NULL,
  version_id         UUID NOT NULL,
  source_question_id UUID NOT NULL,
  target_question_id UUID NOT NULL,
  operator           TEXT NOT NULL,
  expected_value     JSONB,
  FOREIGN KEY (organization_id, version_id, source_question_id)
    REFERENCES public.checklist_questions (organization_id, version_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, version_id, target_question_id)
    REFERENCES public.checklist_questions (organization_id, version_id, id) ON DELETE CASCADE
);
ALTER TABLE public.question_conditions OWNER TO dcmp_migrator;

CREATE TABLE public.checklist_version_snapshots (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      UUID NOT NULL,
  checklist_version_id UUID NOT NULL UNIQUE,
  snapshot             JSONB NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (organization_id, checklist_version_id)
    REFERENCES public.checklist_versions (organization_id, id)
);
ALTER TABLE public.checklist_version_snapshots OWNER TO dcmp_migrator;

\echo NOTICE: S03_stage3 OK (8 entities)
