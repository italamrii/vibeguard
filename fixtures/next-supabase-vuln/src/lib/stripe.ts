import Stripe from 'stripe';

// vg-expect: secrets/provider-key
export const stripe = new Stripe('{{FAKE:stripe_live:main}}', { apiVersion: '2024-06-20' });
