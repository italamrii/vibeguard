import { supabaseAdmin } from '@/lib/supabase/admin';

// Trusts the payload without verifying the Stripe signature.
// vg-expect: endpoints/webhook-without-signature
export async function POST(request: Request) {
  const event = (await request.json()) as { type: string; data: { object: { id: string } } };
  if (event.type === 'checkout.session.completed') {
    await supabaseAdmin.from('orders').update({ status: 'paid' }).eq('stripe_id', event.data.object.id);
  }
  return Response.json({ received: true });
}
