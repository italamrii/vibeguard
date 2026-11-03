import { createClient } from '@/lib/supabase/server-client';
import { supabaseAdmin } from '@/lib/supabase/admin';

// getSession() only decodes the cookie; it does not verify it with Supabase Auth.
// vg-expect: endpoints/unauthenticated-data-access
export async function DELETE(request: Request) {
  const supabase = await createClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  const { id } = (await request.json()) as { id: string };
  await supabaseAdmin.from('notes').delete().eq('id', id);
  return Response.json({ ok: true });
}
