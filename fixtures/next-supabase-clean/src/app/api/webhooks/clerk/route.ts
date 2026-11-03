import { Webhook } from 'svix';
import { supabaseAdmin } from '@/lib/supabase/server';

export async function POST(request: Request) {
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  const evt = wh.verify(await request.text(), Object.fromEntries(request.headers)) as { data: { id: string } };
  await supabaseAdmin().from('profiles').upsert({ id: evt.data.id });
  return Response.json({ ok: true });
}
