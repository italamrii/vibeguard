import { supabaseAdmin } from '@/lib/supabase/admin';

// vg-expect: endpoints/unauthenticated-data-access
export async function DELETE(request: Request) {
  const { userId } = (await request.json()) as { userId: string };
  await supabaseAdmin.from('profiles').delete().eq('id', userId);
  return Response.json({ ok: true });
}
