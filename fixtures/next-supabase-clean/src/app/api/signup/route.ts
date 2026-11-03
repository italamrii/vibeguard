import { createClient } from '@/lib/supabase/server-client';

// Delegates to Supabase Auth, which rate-limits sign-ups itself.
export async function POST(request: Request) {
  const { email, password } = (await request.json()) as { email: string; password: string };
  const supabase = await createClient();
  const { error } = await supabase.auth.signUp({ email, password });
  return error ? new Response(error.message, { status: 400 }) : Response.json({ ok: true });
}
