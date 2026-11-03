/**
 * Deterministic fake credentials, assembled at runtime (ADR-0007).
 *
 * The repository must never contain a secret-shaped literal: GitHub push protection
 * and secret scanning (and every other scanner pointed at this repo) would flag it.
 * Prefixes are therefore split, and bodies come from a seeded PRNG. Values are
 * format-valid so VibeGuard detects them, high-entropy so they pass its look-alike
 * filters, and fake: none was ever issued by any provider.
 */

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const B62 = UPPER + LOWER + DIGITS;
const B64URL = `${B62}-_`;
const B64 = `${B62}+/`;
const HEX = '0123456789abcdef';
const AWS_ID = `${UPPER}234567`;

/** mulberry32: tiny, fast, deterministic. Not for cryptography; these are fixtures. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedOf(label: string): number {
  let h = 2166136261;
  for (const ch of label) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  return h >>> 0;
}

class Gen {
  private readonly next: () => number;
  constructor(label: string) {
    this.next = prng(seedOf(label));
  }
  chars(alphabet: string, n: number): string {
    let s = '';
    for (let i = 0; i < n; i++) s += alphabet[Math.floor(this.next() * alphabet.length)] ?? 'x';
    return s;
  }
}

const j = (...parts: string[]): string => parts.join('');
const b64url = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');

function supabaseJwt(g: Gen, role: 'anon' | 'service_role'): string {
  const header = b64url('{"alg":"HS256","typ":"JWT"}');
  const ref = g.chars(LOWER, 20);
  const payload = b64url(
    JSON.stringify({ iss: 'supabase', ref, role, iat: 1735689600, exp: 2051222400 }),
  );
  return j(header, '.', payload, '.', g.chars(B64URL, 43));
}

function pem(g: Gen, type: 'RSA PRIVATE KEY' | 'PRIVATE KEY', escapeNewlines: boolean): string {
  const lines = ['MIIE' + g.chars(B64, 60)];
  for (let i = 0; i < 24; i++) lines.push(g.chars(B64, 64));
  lines.push(g.chars(B64, 40) + '==');
  const nl = escapeNewlines ? '\\n' : '\n';
  return j('-----BEGIN ', type, '-----', nl, lines.join(nl), nl, '-----END ', type, '-----');
}

export type FakeKind = keyof typeof GENERATORS;

const GENERATORS = {
  stripe_live: (g: Gen) => j('sk', '_live_', '51', g.chars(B62, 97)),
  stripe_restricted: (g: Gen) => j('rk', '_live_', '51', g.chars(B62, 97)),
  stripe_test: (g: Gen) => j('sk', '_test_', '51', g.chars(B62, 97)),
  stripe_publishable: (g: Gen) => j('pk', '_live_', '51', g.chars(B62, 97)),
  aws_key_id: (g: Gen) => j('AK', 'IA', g.chars(AWS_ID, 16)),
  aws_secret: (g: Gen) => g.chars(B64, 40),
  github_classic: (g: Gen) => j('gh', 'p_', g.chars(B62, 36)),
  github_fine: (g: Gen) => j('github', '_pat_', '11', g.chars(B62, 20), '_', g.chars(B62, 59)),
  openai_proj: (g: Gen) =>
    j('sk', '-proj-', g.chars(B64URL, 74), 'T3Blbk', 'FJ', g.chars(B64URL, 74)),
  anthropic: (g: Gen) => j('sk', '-ant-', 'api03-', g.chars(B64URL, 93), 'AA'),
  slack_bot: (g: Gen) =>
    j('xo', 'xb-', g.chars(DIGITS, 12), '-', g.chars(DIGITS, 13), '-', g.chars(B62, 24)),
  slack_webhook: (g: Gen) =>
    j(
      'https://hooks.',
      'slack.com/services/T',
      g.chars(UPPER + DIGITS, 10),
      '/B',
      g.chars(UPPER + DIGITS, 10),
      '/',
      g.chars(B62, 24),
    ),
  sendgrid: (g: Gen) => j('S', 'G.', g.chars(B64URL, 22), '.', g.chars(B64URL, 43)),
  twilio_api_key: (g: Gen) => j('S', 'K', g.chars(HEX, 32)),
  resend: (g: Gen) => j('re', '_', g.chars(B62, 8), '_', g.chars(B62, 24)),
  google_api: (g: Gen) => j('AI', 'za', 'Sy', g.chars(B64URL, 33)),
  supabase_service_jwt: (g: Gen) => supabaseJwt(g, 'service_role'),
  supabase_anon_jwt: (g: Gen) => supabaseJwt(g, 'anon'),
  supabase_secret: (g: Gen) => j('sb', '_secret_', g.chars(B64URL, 32)),
  supabase_publishable: (g: Gen) => j('sb', '_publishable_', g.chars(B64URL, 32)),
  supabase_ref: (g: Gen) => g.chars(LOWER, 20),
  db_password: (g: Gen) => g.chars(B62, 24),
  hex40: (g: Gen) => g.chars(HEX, 40),
  b64_48: (g: Gen) => g.chars(B64, 48),
  password: (g: Gen) =>
    j(g.chars(UPPER, 1), g.chars(LOWER, 6), g.chars(DIGITS, 3), '!', g.chars(B62, 3)),
  b62_99: (g: Gen) => g.chars(B62, 99),
  pem_rsa: (g: Gen) => pem(g, 'RSA PRIVATE KEY', false),
  // Values published in vendor documentation. Detection must ignore them.
  doc_aws_key_id: () => j('AKIA', 'IOSFODNN7EXAMPLE'),
  doc_aws_secret: () => j('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'),
  doc_stripe_test: () => j('sk_test_', '4eC39HqLyjWDarjtT1zdp7dc'),
  pem_pkcs8_escaped: (g: Gen) => pem(g, 'PRIVATE KEY', true),
} satisfies Record<string, (g: Gen) => string>;

export function isFakeKind(kind: string): kind is FakeKind {
  return kind in GENERATORS;
}

/** The value for (kind, label). The same pair always yields the same value. */
export function fake(kind: FakeKind, label = 'default'): string {
  return GENERATORS[kind](new Gen(`${kind}:${label}`));
}

/** Kinds whose values are secrets (as opposed to public-by-design look-alikes and ids). */
export const SECRET_KINDS: ReadonlySet<FakeKind> = new Set<FakeKind>([
  'stripe_live',
  'stripe_restricted',
  'stripe_test',
  'aws_secret',
  'github_classic',
  'github_fine',
  'openai_proj',
  'anthropic',
  'slack_bot',
  'slack_webhook',
  'sendgrid',
  'twilio_api_key',
  'resend',
  'google_api',
  'supabase_service_jwt',
  'supabase_secret',
  'db_password',
  'hex40',
  'b64_48',
  'password',
  'pem_rsa',
  'pem_pkcs8_escaped',
]);
