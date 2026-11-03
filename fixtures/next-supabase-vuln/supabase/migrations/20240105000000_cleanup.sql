drop policy "Own notes" on public.notes;

-- "Fix" for a permissions error on the profile page. The "Own profile" policy is now ignored.
-- vg-expect: supabase/rls-disabled
alter table public.profiles disable row level security;
