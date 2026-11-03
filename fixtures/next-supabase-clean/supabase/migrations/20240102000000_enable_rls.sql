-- RLS is enabled in a separate, later migration: the final state is what counts.
alter table public.profiles enable row level security;
alter table public.notes enable row level security;
alter table public.countries enable row level security;
alter table public.stripe_events enable row level security;
revoke all on public.stripe_events from anon, authenticated;
