-- Force invited users to set their own password on first login.
-- When an admin invites a member we create the auth user with a random temp
-- password and flag the profile; the app blocks everything until the user picks
-- a new password, which clears the flag (server-side, service-role).

alter table profiles
  add column must_change_password boolean not null default false;
