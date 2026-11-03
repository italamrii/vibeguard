create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text
);
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users,
  body text
);
create table public.countries (code text primary key, name text not null);
-- Server-only: written by the Stripe webhook with the service role.
create table public.stripe_events (id text primary key, payload jsonb not null);
create table public.legacy_items (id bigint primary key);

create schema if not exists private;
create table private.audit_log (id bigint primary key, event text);

-- Internal queue, never reachable through the Data API.
create table public.job_queue (id bigint primary key, payload jsonb);
revoke all on public.job_queue from anon, authenticated;
