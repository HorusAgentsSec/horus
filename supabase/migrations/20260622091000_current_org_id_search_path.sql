-- current_org_id() es la base de practicamente todas las politicas RLS. Al ser
-- SECURITY DEFINER sin search_path fijo era vulnerable a secuestro de search_path
-- (un objeto "profiles" malicioso en otro schema antepuesto al path). Fijamos el
-- search_path como ya hacen refresh_community_verdicts y snapshot_epss.
create or replace function current_org_id()
  returns uuid
  language sql
  security definer
  set search_path = public
as $$
  select org_id from profiles where id = auth.uid()
$$;
