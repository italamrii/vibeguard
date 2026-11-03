import { withUser } from '@/lib/with-user';
import { supabaseAdmin } from '@/lib/supabase/server';

export const POST = withUser(async (request, userId) => {
  const { customerId } = (await request.json()) as { customerId: string };
  await supabaseAdmin().from('profiles').update({ stripe_customer_id: customerId }).eq('id', userId);
  return Response.json({ ok: true });
});
