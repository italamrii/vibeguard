import Stripe from 'stripe';
import { supabaseAdmin } from '@/lib/supabase/server';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Authenticated by the Stripe signature, not by a user session.
export async function POST(request: Request) {
  const event = stripe.webhooks.constructEvent(
    await request.text(),
    request.headers.get('stripe-signature')!,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );
  await supabaseAdmin().from('orders').update({ status: 'paid' }).eq('stripe_id', event.id);
  return Response.json({ received: true });
}
