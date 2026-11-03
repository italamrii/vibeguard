const Stripe = require('stripe');

// vg-expect: secrets/provider-key
const live = new Stripe('{{FAKE:stripe_restricted:payments}}');
// Test-mode key: still a credential, reported at low severity.
// vg-expect: secrets/provider-key
const test = new Stripe('{{FAKE:stripe_test:payments}}');

module.exports = { live, test };
