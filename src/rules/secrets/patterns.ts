import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { JWT_PATTERN, supabaseJwtRole } from './jwt.ts';
import { hasRandomLookingBody, isPlaceholder, WEAK_DEFAULT_PASSWORDS } from './placeholders.ts';

/**
 * Provider-specific secret signatures. Regex is the right tool here (ADR-0001 allows it
 * only for secret signatures): the formats are lexical, and many secrets live in files
 * we do not parse (YAML, .env, shell, Markdown).
 *
 * Every pattern:
 *  - is anchored with look-arounds so it does not match inside a longer token;
 *  - uses only bounded quantifiers (linear time; covered by a ReDoS test);
 *  - is gated by cheap lowercase keywords before the regex runs;
 *  - is rejected when the value is a documented example or placeholder, or when its
 *    random-looking body has too little entropy (combined pattern + entropy check).
 */

export type SecretKind = 'key' | 'testKey' | 'keyId' | 'dbUrl' | 'publicByContext';

export interface SecretPattern {
  readonly id: string;
  /** Brand/product name. Not translated. */
  readonly provider: string;
  readonly keywords: readonly string[];
  /** Global regex; capture group `secretGroup` (default 1) is the secret value. */
  readonly regex: RegExp;
  readonly secretGroup?: number;
  readonly kind: SecretKind;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Minimum Shannon entropy (bits/char) of the value after `prefixLength` characters. */
  readonly minEntropy: number;
  readonly prefixLength: number;
  /**
   * Context check. Return `false` to reject the match, or overrides for this occurrence.
   * `text` is the whole file (or line, for streamed files); `index` is the match offset.
   */
  readonly refine?: (
    secret: string,
    match: RegExpExecArray,
    text: string,
    index: number,
  ) =>
    false | { severity?: Severity; confidence?: Confidence; kind?: SecretKind; provider?: string };
}

export interface SecretMatch {
  readonly patternId: string;
  readonly provider: string;
  readonly kind: SecretKind;
  readonly secret: string;
  /** Offset of the secret value within the scanned text. */
  readonly index: number;
  readonly severity: Severity;
  readonly confidence: Confidence;
}

const B = '(?<![A-Za-z0-9_])'; // left boundary for prefixed tokens
const E = '(?![A-Za-z0-9_])'; // right boundary
const BD = '(?<![A-Za-z0-9_-])';
const ED = '(?![A-Za-z0-9_-])';

const LOCAL_DB_HOSTS = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$/i;

/** Window of text before an offset, used for context checks. */
function before(text: string, index: number, n: number): string {
  return text.slice(Math.max(0, index - n), index);
}

function lineAround(text: string, index: number): string {
  const s = text.lastIndexOf('\n', index) + 1;
  const e = text.indexOf('\n', index);
  return text.slice(s, e === -1 ? text.length : e);
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'aws-access-key-id',
    provider: 'AWS access key ID',
    keywords: ['akia', 'asia', 'abia', 'acca'],
    regex: /(?<![A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})(?![A-Za-z0-9])/g,
    kind: 'keyId',
    severity: 'high',
    confidence: 'medium',
    minEntropy: 2.8,
    prefixLength: 4,
  },
  {
    id: 'aws-secret-access-key',
    provider: 'AWS secret access key',
    keywords: ['aws'],
    regex:
      /aws[A-Za-z0-9_.-]{0,20}?(?:secret|sak)[A-Za-z0-9_.-]{0,20}?['"]?\s{0,5}[:=]\s{0,5}['"]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/gi,
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 0,
  },
  {
    id: 'github-token',
    provider: 'GitHub token',
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'],
    regex: new RegExp(`${B}(gh[pousr]_[A-Za-z0-9]{36,251})${E}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 4,
  },
  {
    id: 'github-fine-grained-token',
    provider: 'GitHub fine-grained token',
    keywords: ['github_pat_'],
    regex: new RegExp(`${B}(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})${E}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 11,
  },
  {
    id: 'stripe-live-key',
    provider: 'Stripe live secret key',
    keywords: ['sk_live_', 'rk_live_'],
    regex: new RegExp(`${B}((?:sk|rk)_live_[A-Za-z0-9]{20,247})${E}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 3.8,
    prefixLength: 8,
  },
  {
    id: 'stripe-test-key',
    provider: 'Stripe test secret key',
    keywords: ['sk_test_', 'rk_test_'],
    regex: new RegExp(`${B}((?:sk|rk)_test_[A-Za-z0-9]{20,247})${E}`, 'g'),
    kind: 'testKey',
    severity: 'low',
    confidence: 'high',
    minEntropy: 3.8,
    prefixLength: 8,
  },
  {
    id: 'openai-key',
    provider: 'OpenAI API key',
    keywords: ['sk-proj-', 'sk-svcacct-', 'sk-admin-', 'sk-none-', 't3blbkfj'],
    regex: new RegExp(
      `${BD}(sk-(?:proj|svcacct|admin|None)-[A-Za-z0-9_-]{40,300}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})${ED}`,
      'g',
    ),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 8,
  },
  {
    id: 'anthropic-key',
    provider: 'Anthropic API key',
    keywords: ['sk-ant-'],
    regex: new RegExp(`${BD}(sk-ant-(?:api|admin)\\d{2}-[A-Za-z0-9_-]{80,120})${ED}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 14,
  },
  {
    id: 'slack-token',
    provider: 'Slack token',
    keywords: ['xoxb-', 'xoxp-', 'xoxa-', 'xoxo-', 'xoxs-', 'xoxr-'],
    regex: new RegExp(`${BD}(xox[abposr]-[0-9]{6,20}-[0-9A-Za-z-]{8,200})${ED}`, 'g'),
    kind: 'key',
    severity: 'high',
    confidence: 'high',
    minEntropy: 3.5,
    prefixLength: 5,
  },
  {
    id: 'slack-webhook',
    provider: 'Slack incoming webhook',
    keywords: ['hooks.slack.com'],
    regex:
      /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{24})(?![A-Za-z0-9])/g,
    kind: 'key',
    severity: 'medium',
    confidence: 'high',
    minEntropy: 3.5,
    prefixLength: 33,
  },
  {
    id: 'sendgrid-key',
    provider: 'SendGrid API key',
    keywords: ['sg.'],
    regex: new RegExp(`${BD}(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})${ED}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 3,
  },
  {
    id: 'twilio-api-key',
    provider: 'Twilio API key',
    keywords: ['sk'],
    regex: /(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![A-Za-z0-9])/g,
    kind: 'key',
    severity: 'high',
    confidence: 'medium',
    minEntropy: 3.2,
    prefixLength: 2,
  },
  {
    id: 'resend-key',
    provider: 'Resend API key',
    keywords: ['re_'],
    regex: new RegExp(`${B}(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,32})${E}`, 'g'),
    kind: 'key',
    severity: 'high',
    confidence: 'medium',
    minEntropy: 3.8,
    prefixLength: 3,
  },
  {
    id: 'google-api-key',
    provider: 'Google API key',
    keywords: ['aiza'],
    regex: new RegExp(`${BD}(AIza[0-9A-Za-z_-]{35})${ED}`, 'g'),
    kind: 'key',
    severity: 'medium',
    confidence: 'medium',
    minEntropy: 3.8,
    prefixLength: 4,
    refine: (_secret, _m, text, index) => {
      const line = lineAround(text, index);
      // Gemini / Generative Language API keys share the AIza format and are billable secrets.
      if (/gemini|generativelanguage|generative[_-]?ai|google[_-]?ai/i.test(line)) {
        return { severity: 'critical', confidence: 'high', provider: 'Google AI (Gemini) API key' };
      }
      // Firebase web config keys are public by design (access is enforced by Security Rules).
      const ctx = before(text, index, 300);
      if (/firebase/i.test(line) || (/apiKey/i.test(ctx) && /authDomain|firebase/i.test(text))) {
        return false;
      }
      return {};
    },
  },
  {
    id: 'supabase-service-role-jwt',
    provider: 'Supabase service_role key',
    keywords: ['eyj'],
    regex: new RegExp(JWT_PATTERN.source, 'g'),
    secretGroup: 0,
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 4.0,
    prefixLength: 0,
    // Only service_role keys: the anon key is public, other JWTs are not provider keys.
    refine: (secret) => (supabaseJwtRole(secret) === 'service_role' ? {} : false),
  },
  {
    id: 'supabase-secret-key',
    provider: 'Supabase secret key',
    keywords: ['sb_secret_'],
    regex: new RegExp(`${B}(sb_secret_[A-Za-z0-9_-]{20,128})${ED}`, 'g'),
    kind: 'key',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 3.8,
    prefixLength: 10,
  },
  {
    id: 'database-url-password',
    provider: 'Database connection string',
    keywords: ['://'],
    regex:
      /(?<![A-Za-z0-9+.-])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/([^\s:@/'"`]{1,128}):([^\s@'"`/]{1,256})@([^\s/'"`:?,]{1,253})/gi,
    secretGroup: 2,
    kind: 'dbUrl',
    severity: 'critical',
    confidence: 'high',
    minEntropy: 2.0,
    prefixLength: 0,
    refine: (secret, m) => {
      const host = m[3] ?? '';
      // Local and docker-compose service hosts (single label, e.g. "db") are dev setups.
      if (LOCAL_DB_HOSTS.test(host) || !host.includes('.')) return false;
      if (secret.length < 6 || WEAK_DEFAULT_PASSWORDS.has(secret.toLowerCase())) return false;
      if (/^[[(<]/.test(secret)) return false; // [YOUR-PASSWORD], (password), <password>
      return {};
    },
  },
];

const indexed = new Map<RegExp, RegExp>();
/** Clone of `re` with the `d` flag, so capture-group offsets are exact. */
function withIndices(re: RegExp): RegExp {
  let r = indexed.get(re);
  if (!r) {
    r = new RegExp(re.source, re.flags.includes('d') ? re.flags : `${re.flags}d`);
    indexed.set(re, r);
  }
  return r;
}

/**
 * Find provider secrets in `text`. Overlapping matches are resolved in favour of the
 * earlier pattern in SECRET_PATTERNS (patterns are ordered most-specific first).
 */
export function findSecrets(text: string): SecretMatch[] {
  const lower = text.toLowerCase();
  const out: SecretMatch[] = [];
  const taken: [number, number][] = [];
  for (const p of SECRET_PATTERNS) {
    if (!p.keywords.some((k) => lower.includes(k))) continue;
    const re = withIndices(p.regex);
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const group = p.secretGroup ?? 1;
      const secret = m[group];
      const span = m.indices?.[group];
      if (secret === undefined || secret.length === 0 || span === undefined) continue;
      const index = span[0];
      if (isPlaceholder(secret) || isPlaceholder(m[0])) continue;
      if (!hasRandomLookingBody(secret.slice(p.prefixLength), p.minEntropy)) continue;
      const refined = p.refine ? p.refine(secret, m, text, index) : {};
      if (refined === false) continue;
      const end = index + secret.length;
      if (taken.some(([s, e]) => index < e && end > s)) continue;
      taken.push([index, end]);
      out.push({
        patternId: p.id,
        provider: refined.provider ?? p.provider,
        kind: refined.kind ?? p.kind,
        secret,
        index,
        severity: refined.severity ?? p.severity,
        confidence: refined.confidence ?? p.confidence,
      });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}
