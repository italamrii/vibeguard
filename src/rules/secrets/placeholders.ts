import { shannonEntropy } from '../../core/redaction/redact.ts';

/**
 * Values published in vendor documentation as examples. They are secret-shaped but
 * worthless, and they appear constantly in READMEs, tests and tutorials. Matching them
 * would be a false positive in every project that copied a docs snippet.
 *
 * Each entry is split so that this file itself is not secret-shaped (ADR-0007).
 */
const DOC_EXAMPLES: ReadonlySet<string> = new Set([
  ['AKIA', 'IOSFODNN7EXAMPLE'].join(''), // AWS docs access key id
  ['wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'].join(''), // AWS docs secret key
  ['sk_test_', '4eC39HqLyjWDarjtT1zdp7dc'].join(''), // Stripe docs test key
  ['sk_test_', 'BQokikJOvBiI2HlWgH4olfQ2'].join(''), // Stripe docs test key (older)
  ['pk_test_', 'TYooMQauvdEDq54NiTphI7jx'].join(''), // Stripe docs publishable key
]);

/**
 * Words that mark a value as a placeholder. Matched case-insensitively as substrings,
 * except where noted. Do not add "test" or "demo": `sk_test_…` is a real (if lower
 * severity) Stripe secret, and real keys can contain those letters.
 */
const PLACEHOLDER_MARKERS: readonly RegExp[] = [
  /example/i,
  /sample/i,
  /placeholder/i,
  /your[_-]?(?:api|secret|key|token|password|own|project|anon|service)/i,
  /(?:^|[_-])your(?:$|[_-])/i,
  /x{6,}/i,
  /\*{3,}/,
  /\.{3,}/,
  /…/,
  /<[^>]*>/,
  /\$\{[^}]*\}/,
  /\{\{[^}]*\}\}/,
  /%[A-Z_]+%/,
  /(?:^|[^a-z])(?:change[_-]?me|replace[_-]?me|dummy|redacted|insert[_-]?here|todo|fixme|not[_-]?real)(?:$|[^a-z])/i,
  /(?:0123456789|123456789|abcdefghij|qwertyuiop)/i,
];

/** True when `value` is a documented example or an obvious placeholder. */
export function isPlaceholder(value: string): boolean {
  if (DOC_EXAMPLES.has(value)) return true;
  if (PLACEHOLDER_MARKERS.some((re) => re.test(value))) return true;
  // The same character eight or more times in a row (e.g. sk_live_00000000…).
  if (/(.)\1{7,}/.test(value)) return true;
  return false;
}

/**
 * Real generated credentials are high-entropy. This rejects low-entropy look-alikes such
 * as `sk_live_aaaaabbbbbccccc` that slip past the placeholder markers.
 */
export function hasRandomLookingBody(body: string, minEntropy: number): boolean {
  return body.length > 0 && shannonEntropy(body) >= minEntropy;
}

/**
 * Well-known default credentials (database images, tutorials). Hardcoding one is still
 * poor practice, but in docker-compose files and local URLs it is the expected dev setup
 * and flagging it would drown real findings.
 */
export const WEAK_DEFAULT_PASSWORDS: ReadonlySet<string> = new Set([
  'password',
  'password1',
  'password123',
  'postgres',
  'root',
  'admin',
  'secret',
  'pass',
  'test',
  'mysql',
  'mongo',
  'redis',
  'guest',
  'mysecretpassword',
  'example',
  'changeme',
  'user',
  'pwd',
  'qwerty',
  'letmein',
  'testpassword',
  'testtest',
]);
