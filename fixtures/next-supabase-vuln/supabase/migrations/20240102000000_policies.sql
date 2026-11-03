alter table public.profiles enable row level security;
create policy "Own profile" on public.profiles for select using (auth.uid() = id);

create policy "Own notes" on public.notes for all using (auth.uid() = owner);

alter table public.tmp_payments rename to payments;

create table public.orders (id bigint primary key, user_id uuid not null, status text);
alter table public.orders enable row level security;
-- vg-expect: supabase/permissive-policy
create policy "Anyone can update orders" on public.orders
  for update to anon, authenticated using (true) with check (true);

create table public.documents (id bigint primary key, owner uuid not null, content text);
alter table public.documents enable row level security;
create policy "Read own documents" on public.documents
  for select to authenticated using ((select auth.uid()) = owner);
-- Only checks that the caller is logged in, not that they own the row.
-- vg-expect: supabase/permissive-policy
create policy "Logged in users can delete" on public.documents
  for delete to authenticated using (auth.uid() is not null);

create table public.messages (id bigint primary key, sender uuid, recipient uuid, body text);
alter table public.messages enable row level security;
-- vg-expect: supabase/permissive-policy
create policy "Public messages" on public.messages for select using (true);

create table public.todos (id bigint primary key, user_id uuid not null, title text);
alter table public.todos enable row level security;
create policy "Own todos" on public.todos for update to authenticated using (auth.uid() = user_id);
