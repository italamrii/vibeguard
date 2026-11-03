import { createClient } from '@/lib/supabase/server-client';

export async function POST(request: Request) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const body = (await request.json()) as { status: string };
  await supabase.from('orders').insert({ status: body.status, user_id: user.id });
  return Response.json({ ok: true });
}
