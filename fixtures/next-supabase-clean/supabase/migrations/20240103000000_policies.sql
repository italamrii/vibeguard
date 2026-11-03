create policy "Users read own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
create policy "Users update own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- Temporary wide-open policy, replaced in the next migration.
create policy "tmp" on public.notes for all using (true);

-- vibeguard-ignore-next-line supabase/permissive-policy -- countries is public reference data, read-only by design
create policy "Countries are public" on public.countries for select to anon, authenticated using (true);
