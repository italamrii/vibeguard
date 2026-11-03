import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

// User-scoped client: anon key + the caller's session cookie, so RLS applies.
export async function createClient() {
  const store = await cookies();
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll: () => store.getAll(), setAll: () => {} },
  });
}
