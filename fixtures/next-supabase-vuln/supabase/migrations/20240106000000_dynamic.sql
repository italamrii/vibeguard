-- RLS disabled from inside PL/pgSQL: VibeGuard does not execute DO blocks.
-- vg-expect-miss: supabase/rls-disabled -- DO blocks are not executed; the table is only marked unknown
do $$ begin
  execute 'alter table public.secrets_vault disable row level security';
end $$;
