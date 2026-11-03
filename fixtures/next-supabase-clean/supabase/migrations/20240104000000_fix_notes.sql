drop policy "tmp" on public.notes;
create policy "Owners manage notes" on public.notes
  for all to authenticated
  using ((select auth.uid()) = owner)
  with check ((select auth.uid()) = owner);
alter policy "Owners manage notes" on public.notes rename to "Owners manage their notes";

-- Idempotent re-run: must not reset RLS on the existing table.
create table if not exists public.notes (id uuid primary key);

-- Dropped and recreated with RLS.
drop table public.legacy_items;
create table public.legacy_items (id bigint primary key, owner uuid not null);
alter table public.legacy_items enable row level security;
create policy "Own items" on public.legacy_items
  for select to authenticated using (owner = (select auth.uid()));

create view public.my_notes with (security_invoker = true) as
  select id, body from public.notes;

create function private.purge_user(uid uuid) returns void
language sql security definer as $$ delete from public.notes where owner = uid $$;

-- Trigger functions cannot be called through rpc().
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end $$;

create function public.admin_stats() returns bigint
language sql security definer as $$ select count(*) from public.notes $$;
revoke execute on function public.admin_stats() from public, anon, authenticated;
