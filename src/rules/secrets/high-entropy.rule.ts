import ts from 'typescript';
import { bindingNameOf, calleeName, stringValue, walk } from '../../analysis/ast-utils.ts';
import { CODE_KINDS } from '../../core/discovery/file-kind.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence } from '../../core/findings/severity.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { redactSecret, shannonEntropy } from '../../core/redaction/redact.ts';
import {
  confidenceForPath,
  hardcodedScanApplies,
  isTestPath,
  secretDigest,
  secretsInFile,
  SECRETS_REFERENCES,
} from './common.ts';
import { supabaseJwtRole } from './jwt.ts';
import { findSecrets } from './patterns.ts';
import { isPlaceholder, WEAK_DEFAULT_PASSWORDS } from './placeholders.ts';

type Msg = 'token' | 'password' | 'signingKey';

/** Names that suggest the bound value is a credential. */
const SECRET_NAME =
  /secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd|pwd|passphrase|credential|auth[_-]?key|signing[_-]?key|encryption[_-]?key|jwt[_-]?key|^key$/i;
const PASSWORD_NAME = /passw(?:or)?d|passwd|pwd|passphrase/i;
/**
 * Words that, anywhere in a name, mean the value is something else: a URL, an id, a
 * label, a length limit, a public key, a header name, a storage key name, …
 * Matched against whole words (camelCase / snake_case / kebab-case split), never
 * substrings: "min" must exclude `passwordMinLength` but not `ADMIN_PASSWORD`.
 */
const NOT_A_SECRET_WORDS: ReadonlySet<string> = new Set([
  'public',
  'publishable',
  'anon',
  'site',
  'url',
  'uri',
  'endpoint',
  'host',
  'domain',
  'path',
  'file',
  'dir',
  'name',
  'label',
  'placeholder',
  'message',
  'msg',
  'text',
  'title',
  'description',
  'desc',
  'error',
  'header',
  'field',
  'param',
  'type',
  'format',
  'pattern',
  'regex',
  'regexp',
  'length',
  'len',
  'min',
  'max',
  'count',
  'expiry',
  'expires',
  'expired',
  'expiration',
  'ttl',
  'timeout',
  'enabled',
  'required',
  'hint',
  'policy',
  'storage',
  'query',
  'route',
  'event',
  'action',
  'mode',
  'version',
  'algorithm',
  'alg',
  'prefix',
  'suffix',
  'id',
  'ids',
  'hash',
  'sha',
  'checksum',
  'integrity',
  'nonce',
  'rounds',
  'cost',
  'confirm',
  'confirmation',
  'reset',
  'forgot',
  'strength',
  'visible',
  'show',
  'toggle',
  'input',
  'form',
  'schema',
  'validator',
  'rule',
  'rules',
  'i18n',
  'translation',
  'missing',
  'invalid',
  'label',
  'docs',
  'link',
  'status',
  'state',
  'loading',
  'ref',
]);

/** Split an identifier into lowercase words: `apiKeyHeader` → api, key, header. */
export function nameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[\s_.-]+/)
    .filter((w) => w.length > 0)
    .map((w) => w.toLowerCase());
}

function isExcludedName(name: string): boolean {
  return nameWords(name).some((w) => NOT_A_SECRET_WORDS.has(w));
}

export interface Candidate {
  readonly kind: Msg;
  readonly confidence: Confidence;
}

const HEX = /^[0-9a-f]+$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Decide whether `value`, bound to `name`, is a hardcoded credential. Exported for tests.
 * The provider-key rule owns anything a provider signature recognises, so we skip those.
 */
export function classifyCandidate(name: string, rawValue: string): Candidate | undefined {
  if (!SECRET_NAME.test(name) || isExcludedName(name)) return undefined;
  const value = rawValue.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  if (value.length === 0 || /\s/.test(value)) return undefined;
  if (isPlaceholder(value)) return undefined;
  // URLs, relative paths, anchors, env references. (A leading "/" alone is not excluded:
  // base64 secrets can start with it, and real absolute paths fail the entropy checks.)
  if (/^(?:[a-z][a-z0-9+.-]*:\/\/|\.{1,2}\/|#|process\.env|import\.meta)/i.test(value))
    return undefined;
  if (UUID.test(value)) return undefined;
  if (findSecrets(value).length > 0) return undefined; // provider-key reports it
  const role = supabaseJwtRole(value);
  if (role === 'anon') return undefined; // public by design

  if (PASSWORD_NAME.test(name)) {
    if (Array.from(value).length < 8 || WEAK_DEFAULT_PASSWORDS.has(value.toLowerCase()))
      return undefined;
    if (/^[A-Za-z_]+$/.test(value) && /^[A-Z_]+$|^[a-z]+(?:[A-Z][a-z]+)+$/.test(value))
      return undefined; // CONSTANT_NAME / camelCase
    if (shannonEntropy(value) < 2.5) return undefined;
    return { kind: 'password', confidence: 'medium' };
  }

  if (value.length < 16) return undefined;
  if (!/\d/.test(value) || !/[a-z]/i.test(value)) return undefined; // identifiers, words
  if (HEX.test(value)) {
    return value.length >= 32 && shannonEntropy(value) >= 3.0
      ? { kind: 'token', confidence: 'medium' }
      : undefined;
  }
  if (!/^[A-Za-z0-9+/=_\-.~:]+$/.test(value)) return undefined; // prose, code, punctuation
  return shannonEntropy(value) >= 3.5 ? { kind: 'token', confidence: 'medium' } : undefined;
}

/** Calls whose given argument is a signing/encryption key (index is 0-based). */
const KEY_ARGUMENT: Readonly<Record<string, number>> = {
  'jwt.sign': 1,
  'jwt.verify': 1,
  'jsonwebtoken.sign': 1,
  'jsonwebtoken.verify': 1,
  sign: 1,
  verify: 1,
  'crypto.createHmac': 1,
  createHmac: 1,
  'crypto.createCipheriv': 1,
  createCipheriv: 1,
  'CryptoJS.AES.encrypt': 1,
  'CryptoJS.AES.decrypt': 1,
  'CryptoJS.HmacSHA256': 1,
};

/** `key: value`, `key = value`, `"key": "value"` in config/text files. */
const KV_LINE =
  /(?:^|[\s{,])["']?([A-Za-z_][A-Za-z0-9_.-]{1,63})["']?\s{0,5}[:=]\s{0,5}["']?([^\s"'#,;]{8,512})["']?/g;

export const highEntropyRule = defineRule<Msg>({
  meta: {
    id: 'secrets/high-entropy',
    family: 'secrets',
    defaultSeverity: 'high',
    cwe: [798, 259],
    references: [...SECRETS_REFERENCES],
    docs: {
      title: {
        en: 'Hardcoded secret, token or password',
        ar: 'سرّ أو رمز أو كلمة مرور مكتوبة مباشرة في الشيفرة',
      },
      summary: {
        en: 'A value bound to a secret-like name (apiKey, jwtSecret, password, …) looks like a real credential: it is long, random and not a placeholder. It does not match a known provider format, so VibeGuard cannot be certain; review it. Typical cases are JWT signing secrets, session secrets, webhook secrets and admin passwords.',
        ar: 'قيمة مرتبطة باسم يوحي بالسرية (apiKey أو jwtSecret أو password…) تبدو بيانات اعتماد حقيقية: طويلة وعشوائية وليست قيمة شكلية. لا تطابق صيغة مزوّد معروف، لذا لا يستطيع VibeGuard الجزم؛ راجعها. من أمثلتها أسرار توقيع JWT وأسرار الجلسات وأسرار webhooks وكلمات مرور المدير.',
      },
      remediation: {
        text: {
          en: 'If it is real: rotate it, read it from a server-side environment variable, and fail fast when it is missing (no hardcoded fallback). Generate signing secrets with a CSPRNG (openssl rand -base64 48). If it is not a secret, rename the variable or add a suppression with the reason.',
          ar: 'إن كانت حقيقية: غيّرها، واقرأها من متغير بيئة على الخادم، وأوقف التشغيل فورًا عند غيابها (دون قيمة احتياطية مكتوبة في الشيفرة). أنشئ أسرار التوقيع بمولّد عشوائي آمن (openssl rand -base64 48). وإن لم تكن سرًّا، فغيّر اسم المتغير أو أضف تعليق كتم مع ذكر السبب.',
        },
        codeLanguage: 'ts',
        vulnerable: `const JWT_SECRET = process.env.JWT_SECRET || 'k3P9…hardcoded…';
const token = jwt.sign({ sub: user.id }, JWT_SECRET);`,
        fixed: `const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set (>= 32 random bytes)');
}
const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1h' });`,
      },
    },
    messages: {
      token: {
        en: '"{name}" is assigned a high-entropy literal that looks like a real credential.',
        ar: 'أُسندت إلى "{name}" قيمة حرفية عالية العشوائية تبدو بيانات اعتماد حقيقية.',
      },
      password: {
        en: '"{name}" is assigned a hardcoded password.',
        ar: 'أُسندت إلى "{name}" كلمة مرور مكتوبة مباشرة.',
      },
      signingKey: {
        en: '{name}() is called with a hardcoded signing/encryption key.',
        ar: 'تُستدعى الدالة {name}() بمفتاح توقيع أو تشفير مكتوب مباشرة.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files()) {
      if (!hardcodedScanApplies(file)) continue;
      const known = new Set((await secretsInFile(ctx, file)).map((m) => m.secret));

      if (CODE_KINDS.includes(file.kind)) {
        const parsed = await ctx.parseTs(file);
        if (!parsed) continue;
        const sf = parsed.sourceFile;
        walk(sf, (node) => {
          if (ts.isCallExpression(node)) {
            const callee = calleeName(node);
            const idx = callee === undefined ? undefined : KEY_ARGUMENT[callee];
            const arg = idx === undefined ? undefined : node.arguments[idx];
            const value = arg ? stringValue(arg) : undefined;
            if (arg && value !== undefined && callee !== undefined && !known.has(value)) {
              const c = keep(classifyCandidate('signingPassword', value), file.relPath);
              if (c)
                out.push(make(file.relPath, sf, arg, value, 'signingKey', callee, c.confidence));
            }
            return undefined;
          }
          const value = stringValue(node);
          if (value === undefined || known.has(value)) return undefined;
          // A literal used as a call's key argument is handled above.
          if (ts.isCallExpression(node.parent)) return undefined;
          const name = bindingNameOf(node);
          if (name === undefined) return undefined;
          const c = keep(classifyCandidate(name, value), file.relPath);
          if (c) out.push(make(file.relPath, sf, node, value, c.kind, name, c.confidence));
          return undefined;
        });
        continue;
      }

      const textConfidence: Confidence = file.kind === 'text' ? 'low' : 'medium';
      for await (const { text, line } of ctx.lines(file)) {
        if (text.length > 4096) continue; // minified / data blobs
        KV_LINE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = KV_LINE.exec(text)) !== null) {
          const name = m[1] ?? '';
          const value = m[2] ?? '';
          if (known.has(value)) continue;
          const c = keep(classifyCandidate(name.split('.').pop() ?? name, value), file.relPath);
          if (!c) continue;
          const confidence: Confidence = textConfidence === 'low' ? 'low' : c.confidence;
          out.push({
            location: { file: file.relPath, line, column: m.index + m[0].indexOf(value) + 1 },
            messageId: c.kind,
            params: { name },
            evidence: redactSecret(value),
            confidence: confidenceForPath(confidence, file.relPath),
            ...(c.kind === 'password' ? { severity: 'high' as const } : {}),
            fingerprintKey: `${name}:${secretDigest(value)}`,
          });
        }
      }
    }
    return out;
  },
});

/**
 * Human-chosen passwords and signing strings in test code ('test-secret', 'hunter2!')
 * are test data, not leaks. Random-looking tokens in tests are still reported (real keys
 * do get pasted into integration tests), with confidence lowered by confidenceForPath.
 */
function keep(c: Candidate | undefined, relPath: string): Candidate | undefined {
  if (c?.kind === 'password' && isTestPath(relPath)) return undefined;
  return c;
}

function make(
  file: string,
  sf: ts.SourceFile,
  node: ts.Node,
  value: string,
  kind: Msg,
  name: string,
  confidence: Confidence,
): FindingInput<Msg> {
  const pos = nodePosition(sf, node);
  return {
    location: {
      file,
      line: pos.line,
      column: pos.column + 1,
      endLine: pos.endLine,
      endColumn: pos.endColumn,
    },
    messageId: kind,
    params: { name },
    evidence: redactSecret(value),
    confidence: confidenceForPath(confidence, file),
    fingerprintKey: `${name}:${secretDigest(value)}`,
  };
}
