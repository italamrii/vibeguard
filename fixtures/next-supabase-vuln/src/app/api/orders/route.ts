import { createClient } from '@/lib/supabase/server-client';

// No user check: only RLS stands between anonymous callers and the orders table.
// vg-expect: endpoints/unauthenticated-data-access
export async function POST(request: Request) {
  const supabase = await createClient();
  const body = (await request.json()) as { status: string };
  await supabase.from('orders').insert({ status: body.status });
  return Response.json({ ok: true });
}
