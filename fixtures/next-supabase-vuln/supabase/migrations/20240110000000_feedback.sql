-- The second statement has a typo, so it cannot be parsed. RLS state of feedback is unknown.
-- vg-expect: supabase/rls-disabled
create table public.feedback (id bigint generated always as identity primary key, body text);
alter table public.feedback enable row level securty;
