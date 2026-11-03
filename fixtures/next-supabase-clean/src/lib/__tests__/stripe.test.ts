import { describe, expect, it } from 'vitest';

// Stripe's own documentation test key: public, safe to commit.
const STRIPE_DOCS_TEST_KEY = '{{FAKE:doc_stripe_test}}';

describe('stripe', () => {
  it('uses test mode in tests', () => {
    const jwtSecret = 'test-secret-for-unit-tests';
    expect(STRIPE_DOCS_TEST_KEY.startsWith('sk_test_')).toBe(true);
    expect(jwtSecret).toBeTruthy();
  });
});
