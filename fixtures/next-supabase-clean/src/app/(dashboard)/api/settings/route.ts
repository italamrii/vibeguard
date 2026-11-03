import { supabaseAdmin } from '@/lib/supabase/server';

// URL is /api/settings: the (dashboard) route group is not part of the path.
// Protected by src/middleware.ts (matcher /api/settings/:path*).
export async function PATCH(request: Request) {
  const body = (await request.json()) as { theme: string; userId: string };
  await supabaseAdmin().from('profiles').update({ theme: body.theme }).eq('id', body.userId);
  return Response.json({ ok: true });
}
