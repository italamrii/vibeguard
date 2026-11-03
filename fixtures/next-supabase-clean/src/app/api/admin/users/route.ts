import { supabaseAdmin } from '@/lib/supabase/server';

// Protected by src/middleware.ts (matcher /api/admin/:path*).
export async function DELETE(request: Request) {
  const { userId } = (await request.json()) as { userId: string };
  await supabaseAdmin().from('profiles').delete().eq('id', userId);
  return Response.json({ ok: true });
}
