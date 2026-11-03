-- FAKE fixture schema. Intentionally vulnerable: do not reuse.
create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  stripe_customer_id text
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users,
  body text
);
-- RLS on, but the only policy is dropped in a later migration (final state wins).
-- vg-expect: supabase/rls-no-policies
alter table public.notes enable row level security;

-- Renamed later to public.payments; never gets RLS.
-- vg-expect: supabase/rls-disabled
create table public.tmp_payments (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null
);

-- Quoted, mixed-case, schema-qualified name.
-- vg-expect: supabase/rls-disabled
create table "public"."Invoices" (id bigint primary key, customer text, total numeric);

-- Not exposed through the Data API: not a finding.
create schema if not exists private;
create table private.audit_log (id bigint primary key, event text);
