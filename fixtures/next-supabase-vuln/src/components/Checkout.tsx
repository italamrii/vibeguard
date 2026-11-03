'use client';
import { loadStripe } from '@stripe/stripe-js';

// Publishable keys are public by design: not a finding.
const stripePromise = loadStripe('{{FAKE:stripe_publishable:main}}');

export function Checkout() {
  return <button onClick={async () => (await stripePromise)?.redirectToCheckout({ sessionId: 's' })}>Pay</button>;
}
