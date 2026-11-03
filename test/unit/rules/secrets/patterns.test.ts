import { describe, expect, it } from 'vitest';
import { findSecrets, SECRET_PATTERNS } from '../../../../src/rules/secrets/patterns.ts';
import { isPlaceholder } from '../../../../src/rules/secrets/placeholders.ts';
import { fake } from '../../../helpers/fake-secrets.ts';

// All secret-shaped strings are assembled at runtime (ADR-0007).
const j = (...p: string[]): string => p.join('');
const ids = (text: string): string[] => findSecrets(text).map((m) => m.patternId);

interface Case {
  /** Text containing a real-looking secret: must be found by `pattern`. */
  readonly positive: string;
  /** Look-alikes: documentation examples, placeholders, test values, near misses. */
  readonly negatives: readonly string[];
}

const CASES: Record<string, Case> = {
  'aws-access-key-id': {
    positive: `AWS_ACCESS_KEY_ID=${fake('aws_key_id', 't')}`,
    negatives: [
      `AWS_ACCESS_KEY_ID=${fake('doc_aws_key_id')}`, // AWS docs example
      j('AWS_ACCESS_KEY_ID=AKIA', 'XXXXXXXXXXXXXXXX'), // placeholder
      j('id: AKIA', 'AAAAAAAAAAAAAAAA'), // zero entropy
      j('xAKIA', 'Q3RZ7TJKLMNPQ2W5'), // embedded in a longer token
    ],
  },
  'aws-secret-access-key': {
    positive: `aws_secret_access_key = ${fake('aws_secret', 't')}`,
    negatives: [
      `aws_secret_access_key = ${fake('doc_aws_secret')}`,
      'aws_secret_access_key = YOUR_SECRET_ACCESS_KEY_GOES_HERE_PLEASE1',
      `some_other_secret = ${fake('aws_secret', 't')}`, // no AWS context: not this pattern
    ],
  },
  'github-token': {
    positive: `token: ${fake('github_classic', 't')}`,
    negatives: [
      j('ghp_', 'x'.repeat(36)),
      j('ghp_', 'your_token_here_your_token_here_12345'),
      j('ghp_', 'abc123'),
    ],
  },
  'github-fine-grained-token': {
    positive: `GH=${fake('github_fine', 't')}`,
    negatives: [
      j('github_pat_', '11', 'A'.repeat(20), '_', 'B'.repeat(59)),
      j('github_pat_', 'example'),
    ],
  },
  'stripe-live-key': {
    positive: `new Stripe('${fake('stripe_live', 't')}')`,
    negatives: [
      j('sk_live_', 'your_key_here'),
      j('sk_live_', '0'.repeat(30)),
      fake('stripe_publishable', 't'), // publishable keys are public
      j('sk_live_', '…'),
    ],
  },
  'stripe-test-key': {
    positive: `STRIPE=${fake('stripe_test', 't')}`,
    negatives: [fake('doc_stripe_test'), j('sk_test_', 'xxxxxxxxxxxxxxxxxxxxxxxx')],
  },
  'openai-key': {
    positive: `apiKey: '${fake('openai_proj', 't')}'`,
    negatives: [
      j('sk-proj-', '...'),
      j('sk-proj-', 'YOUR_OPENAI_API_KEY_HERE_YOUR_OPENAI_API_KEY'),
      'sk-1234',
    ],
  },
  'anthropic-key': {
    positive: `ANTHROPIC_API_KEY=${fake('anthropic', 't')}`,
    negatives: [j('sk-ant-', 'api03-', 'x'.repeat(95)), j('sk-ant-', '...')],
  },
  'slack-token': {
    positive: `SLACK=${fake('slack_bot', 't')}`,
    negatives: [
      j('xoxb-', 'your-token'),
      j('xoxb-', '123456789012-1234567890123-', 'x'.repeat(24)),
    ],
  },
  'slack-webhook': {
    positive: `url: ${fake('slack_webhook', 't')}`,
    negatives: [j('https://hooks.', 'slack.com/services/T00000000/B00000000/', 'X'.repeat(24))],
  },
  'sendgrid-key': {
    positive: `setApiKey('${fake('sendgrid', 't')}')`,
    negatives: [j('SG.', 'x'.repeat(22), '.', 'x'.repeat(43)), 'SG.your-api-key'],
  },
  'twilio-api-key': {
    positive: `key = '${fake('twilio_api_key', 't')}'`,
    negatives: [j('SK', '0'.repeat(32)), j('SK', 'deadbeef'.repeat(2))],
  },
  'resend-key': {
    positive: `new Resend('${fake('resend', 't')}')`,
    negatives: [j('re_', '123456789', '_your_api_key_here'), j('re_', 'xxxxxxxx_', 'x'.repeat(24))],
  },
  'google-api-key': {
    positive: `const MAPS = '${fake('google_api', 't')}';`,
    negatives: [
      // Firebase web config: public by design.
      `const firebaseConfig = { apiKey: '${fake('google_api', 'f')}', authDomain: 'x.firebaseapp.com' };`,
      `VITE_FIREBASE_API_KEY=${fake('google_api', 'f')}`,
      j('AIza', 'X'.repeat(35)),
    ],
  },
  'supabase-service-role-jwt': {
    positive: `SUPABASE_SERVICE_ROLE_KEY=${fake('supabase_service_jwt', 't')}`,
    negatives: [
      `NEXT_PUBLIC_SUPABASE_ANON_KEY=${fake('supabase_anon_jwt', 't')}`, // anon key is public
      j(
        'eyJhbGciOiJIUzI1NiJ9',
        '.',
        Buffer.from('{"sub":"123","name":"x"}').toString('base64url'),
        '.',
        'c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWc',
      ), // generic JWT
    ],
  },
  'supabase-secret-key': {
    positive: `createClient(url, '${fake('supabase_secret', 't')}')`,
    negatives: [fake('supabase_publishable', 't'), j('sb_secret_', 'your-secret-key-here')],
  },
  'database-url-password': {
    positive: `DATABASE_URL=postgresql://postgres.abc:${fake('db_password', 't')}@aws-0-eu-central-1.pooler.supabase.com:5432/postgres`,
    negatives: [
      'postgres://postgres:postgres@localhost:5432/app',
      'postgres://postgres:postgres@db:5432/app', // docker-compose service name
      `mongodb://root:${fake('db_password', 'x')}@mongo:27017/app`, // single-label host
      'postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijklmnopqrst.supabase.co:5432/postgres',
      'postgres://user:password@example.com/db',
      'postgres://user:${DB_PASSWORD}@prod.db.internal/app',
    ],
  },
};

describe('secret patterns', () => {
  it('has a positive and negative test case for every pattern', () => {
    expect(Object.keys(CASES).sort()).toEqual(SECRET_PATTERNS.map((p) => p.id).sort());
    for (const c of Object.values(CASES)) expect(c.negatives.length).toBeGreaterThan(0);
  });

  describe.each(Object.entries(CASES))('%s', (id, c) => {
    it('detects the real-looking value', () => {
      expect(ids(c.positive)).toContain(id);
    });
    it.each(c.negatives.map((n, i) => [i, n] as const))('ignores look-alike #%i', (_i, text) => {
      expect(ids(text)).not.toContain(id);
    });
  });

  it('reports exact offsets of the secret value', () => {
    const key = fake('stripe_live', 'o');
    const text = `x = '${key}';`;
    const [m] = findSecrets(text);
    expect(m?.secret).toBe(key);
    expect(text.slice(m?.index, (m?.index ?? 0) + key.length)).toBe(key);
  });

  it('reports the password of a database URL, not the whole URL', () => {
    const pw = fake('db_password', 'o');
    const [m] = findSecrets(`postgresql://app:${pw}@db.prod.acme-corp.net:5432/app`);
    expect(m).toMatchObject({ patternId: 'database-url-password', secret: pw, kind: 'dbUrl' });
  });

  it('upgrades Google keys used for Gemini to critical', () => {
    const [m] = findSecrets(`const genAI = new GoogleGenerativeAI('${fake('google_api', 'g')}');`);
    expect(m).toMatchObject({ severity: 'critical', provider: 'Google AI (Gemini) API key' });
  });

  it('classifies Stripe test keys as low severity', () => {
    expect(findSecrets(fake('stripe_test', 's'))[0]).toMatchObject({
      severity: 'low',
      kind: 'testKey',
    });
  });

  it('runs in linear time on adversarial input (ReDoS guard)', () => {
    const inputs = [
      'aws_'.repeat(50_000),
      j('postgres://', 'a'.repeat(50_000)),
      j('postgres://a:', 'b'.repeat(50_000)),
      'eyJ'.repeat(40_000),
      j('sk_live_', 'a'.repeat(100_000)),
      'xoxb-1234567-'.repeat(10_000),
      'SG.'.repeat(40_000),
      'AIza'.repeat(30_000),
    ];
    for (const input of inputs) {
      const t0 = performance.now();
      findSecrets(input);
      expect(performance.now() - t0, input.slice(0, 20)).toBeLessThan(250);
    }
  });
});

describe('isPlaceholder', () => {
  it.each([
    'your-api-key',
    'YOUR_SECRET_KEY',
    'xxxxxxxxxxxx',
    '<your-token>',
    '${STRIPE_KEY}',
    '{{ secrets.KEY }}',
    'change-me-please',
    'sk_live_...',
    'insert_here',
    'abc123example',
  ])('treats %j as a placeholder', (v) => {
    expect(isPlaceholder(v)).toBe(true);
  });

  it.each([fake('stripe_live', 'p'), fake('openai_proj', 'p'), fake('db_password', 'p')])(
    'does not treat real-looking values as placeholders',
    (v) => {
      expect(isPlaceholder(v)).toBe(false);
    },
  );
});
