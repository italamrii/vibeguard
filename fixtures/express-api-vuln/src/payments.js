const Stripe = require('stripe');

// vg-expect: secrets/provider-key
const live = new Stripe('{{FAKE:stripe_restricted:payments}}');
// Test-mode key: still a credential, reported by its own low-severity rule.
// vg-expect: secrets/provider-key-test
const test = new Stripe('{{FAKE:stripe_test:payments}}');

module.exports = { live, test };
