'use client';
import { loadStripe } from '@stripe/stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
const fallbackPublishableKey = '{{FAKE:stripe_publishable:main}}';

export function Checkout() {
  return <button onClick={async () => (await stripePromise)?.redirectToCheckout({ sessionId: fallbackPublishableKey })}>Pay</button>;
}
