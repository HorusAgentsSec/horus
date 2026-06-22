-- Drift catch-up: phishing_schedules, phishing_contacts y las columnas extra de
-- phishing_targets existen en la DB pero nunca llegaron a una migracion (se crearon
-- fuera del flujo). Esta migracion las captura para que un `db reset` / deploy nuevo
-- reproduzca el esquema real. Todo con guards (IF NOT EXISTS / DROP POLICY IF EXISTS)
-- para que aplicarla sobre la DB viva sea idempotente (no-op donde ya existe).
--
-- Esquema introspeccionado del proyecto via PostgREST OpenAPI.

-- ── phishing_contacts: destinatarios reutilizables de campañas programadas ──────
create table if not exists phishing_contacts (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations(id) on delete cascade,
  name        text not null,
  email       text not null,
  department  text,
  created_at  timestamptz not null default now(),
  unique (org_id, email)
);
create index if not exists phishing_contacts_org_idx on phishing_contacts (org_id);
alter table phishing_contacts enable row level security;
drop policy if exists "org_isolation" on phishing_contacts;
create policy "org_isolation" on phishing_contacts using (org_id = current_org_id());

-- ── phishing_schedules: campañas de phishing recurrentes (cron) ─────────────────
create table if not exists phishing_schedules (
  id                uuid primary key default gen_random_uuid(),
  org_id            uuid not null references organizations(id) on delete cascade,
  name              text not null,
  cron_expression   text not null,
  objective         text not null default 'click'
                    check (objective in ('click', 'credentials', 'report')),
  contact_ids       uuid[] not null default '{}',
  context_asset_ids uuid[] not null default '{}',
  enabled           boolean not null default true,
  created_at        timestamptz not null default now()
);
create index if not exists phishing_schedules_org_idx on phishing_schedules (org_id);
alter table phishing_schedules enable row level security;
drop policy if exists "org_isolation" on phishing_schedules;
create policy "org_isolation" on phishing_schedules using (org_id = current_org_id());

-- ── phishing_targets: columnas añadidas para el flujo de contactos/programado ───
-- El scheduler inserta name/email del contacto directamente (sin employee_id), asi
-- que employee_id pasa a ser nullable y se añaden las columnas de contacto/pretexto.
alter table phishing_targets add column if not exists employee_name  text;
alter table phishing_targets add column if not exists employee_email text;
alter table phishing_targets add column if not exists email_pretext  text;
alter table phishing_targets alter column employee_id drop not null;
