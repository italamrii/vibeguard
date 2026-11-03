import { withAuth } from '@/lib/with-auth';
import { supabaseAdmin } from '@/lib/supabase/admin';

// vg-expect: endpoints/unauthenticated-data-access
export const POST = withAuth(async (request: Request) => {
  const { customerId } = (await request.json()) as { customerId: string };
  await supabaseAdmin.from('profiles').update({ stripe_customer_id: customerId }).eq('id', customerId);
  return Response.json({ ok: true });
});
