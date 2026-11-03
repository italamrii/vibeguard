-- "Quick fix" that made every todo editable by anyone logged in.
-- vg-expect: supabase/permissive-policy
alter policy "Own todos" on public.todos using (true);

-- vg-expect: supabase/security-definer-view
create view public.user_emails as select id, email from auth.users;

-- vg-expect: supabase/security-definer-function
create function public.delete_user(uid uuid) returns void
language sql security definer as $$ delete from auth.users where id = uid $$;

create table public.secrets_vault (id bigint primary key, owner uuid, value text);
alter table public.secrets_vault enable row level security;
create policy "Own secrets" on public.secrets_vault for select using (auth.uid() = owner);
