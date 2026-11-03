import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { joinRedacted, redactSecret, scrubText } from '../../core/redaction/redact.ts';
import {
  confidenceForPath,
  hardcodedScanApplies,
  secretDigest,
  SECRETS_REFERENCES,
} from './common.ts';
import { isPlaceholder } from './placeholders.ts';

type Msg = 'pemKey' | 'encryptedPemKey' | 'serviceAccount';

const HEADER =
  /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/g;
const SERVICE_ACCOUNT = /"type"\s*:\s*"service_account"/;
const PRIVATE_KEY_FIELD = /"private_key"\s*:\s*"/;
/** Real keys have hundreds of base64 characters; docs examples have "..." or a few. */
const MIN_BODY_CHARS = 64;
const MAX_BODY_SCAN = 16_384;

interface PemHit {
  readonly index: number;
  readonly header: string;
  readonly body: string;
  readonly encrypted: boolean;
}

/**
 * Strip the wrapping a PEM line may carry when embedded in code or JSON: quotes, string
 * concatenation (`+`), commas, and literal `\n` / `\r` escapes.
 */
function unwrapLine(line: string): string {
  return line.replace(/\\[nr]/g, '').replace(/^[\s'"`+,(]+|[\s'"`+,;)]+$/g, '');
}

const BASE64_LINE = /^[A-Za-z0-9+/=]{16,}$/;
const PEM_HEADER_LINE = /^(?:Proc-Type|DEK-Info|Comment|Version):/i;

/**
 * Find PEM private-key blocks, including ones embedded in JSON or code strings with `\n`
 * escapes. The body must be *consecutive* base64 lines directly after the header (optional
 * RFC 1421 header lines allowed): counting base64-looking characters anywhere in the
 * following text would treat ordinary code as a key body.
 */
export function findPemPrivateKeys(text: string): PemHit[] {
  const hits: PemHit[] = [];
  HEADER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HEADER.exec(text)) !== null) {
    const after = m.index + m[0].length;
    const window = text.slice(after, after + MAX_BODY_SCAN);
    const segments = window.split(/\r?\n|\\n/);
    let body = '';
    let encrypted = /ENCRYPTED/.test(m[1] ?? '');
    let started = false;
    for (const raw of segments) {
      const line = unwrapLine(raw);
      if (line === '') {
        if (started) break;
        continue;
      }
      if (!started && PEM_HEADER_LINE.test(line)) {
        if (/ENCRYPTED/i.test(line)) encrypted = true;
        continue;
      }
      if (line.startsWith('-----END')) break;
      if (!BASE64_LINE.test(line)) break;
      started = true;
      body += line;
    }
    if (body.length < MIN_BODY_CHARS || isPlaceholder(body)) continue;
    hits.push({ index: m.index, header: m[0], body, encrypted });
  }
  return hits;
}

export const privateKeyRule = defineRule<Msg>({
  meta: {
    id: 'secrets/private-key',
    family: 'secrets',
    defaultSeverity: 'critical',
    cwe: [321, 798],
    references: [
      ...SECRETS_REFERENCES,
      'https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys',
    ],
    docs: {
      title: { en: 'Private key committed to the repository', ar: 'مفتاح خاص مُودَع في المستودع' },
      summary: {
        en: 'A private key (TLS/SSH/JWT signing key, or a Google Cloud / Firebase service-account key file) is stored in the project. Whoever holds it can impersonate your server, sign tokens your backend trusts, or act as your service account with full Admin SDK access, bypassing Firebase Security Rules.',
        ar: 'مفتاح خاص (مفتاح TLS أو SSH أو مفتاح توقيع JWT، أو ملف مفتاح حساب خدمة Google Cloud / Firebase) محفوظ داخل المشروع. من يحوزه يستطيع انتحال هوية خادمك، أو توقيع رموز يثق بها الخادم، أو العمل باسم حساب الخدمة بصلاحيات Admin SDK الكاملة متجاوزًا قواعد أمان Firebase.',
      },
      remediation: {
        text: {
          en: 'Revoke the key now (delete the service-account key in Google Cloud IAM, or reissue the certificate / SSH key). Remove the file, add the pattern to .gitignore, and purge it from git history. Provide the key at runtime through your host’s secret manager or a single environment variable, or use keyless auth (workload identity federation).',
          ar: 'ألغِ المفتاح فورًا (احذف مفتاح حساب الخدمة من Google Cloud IAM، أو أعد إصدار الشهادة أو مفتاح SSH). احذف الملف، وأضف نمطه إلى .gitignore، وامسحه من سجل git. وفّر المفتاح وقت التشغيل عبر مدير الأسرار لدى الاستضافة أو متغير بيئة واحد، أو استخدم مصادقة دون مفاتيح (workload identity federation).',
        },
        codeLanguage: 'ts',
        vulnerable: `// firebase-admin.ts
import { cert, initializeApp } from 'firebase-admin/app';
import serviceAccount from './service-account.json'; // committed key file
initializeApp({ credential: cert(serviceAccount) });`,
        fixed: `// firebase-admin.ts (server only)
import { applicationDefault, cert, initializeApp } from 'firebase-admin/app';

const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON; // set in the host's secret store
initializeApp({
  credential: json ? cert(JSON.parse(json)) : applicationDefault(),
});
// .gitignore:  *service-account*.json  *.pem  *.key`,
      },
    },
    messages: {
      pemKey: {
        en: 'A PEM private key ({keyType}) is stored in this file.',
        ar: 'مفتاح خاص بصيغة PEM ({keyType}) محفوظ في هذا الملف.',
      },
      encryptedPemKey: {
        en: 'A passphrase-protected PEM private key ({keyType}) is stored in this file. It is only as safe as its passphrase, which is often nearby.',
        ar: 'مفتاح خاص بصيغة PEM ({keyType}) محمي بعبارة مرور محفوظ في هذا الملف. أمانه بقدر أمان عبارة المرور التي تكون غالبًا قريبة منه.',
      },
      serviceAccount: {
        en: 'A Google Cloud / Firebase service-account key for project {project} is stored in this file. It grants Admin SDK access that bypasses Security Rules.',
        ar: 'مفتاح حساب خدمة Google Cloud / Firebase للمشروع {project} محفوظ في هذا الملف، ويمنح صلاحيات Admin SDK التي تتجاوز قواعد الأمان.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files()) {
      if (!hardcodedScanApplies(file)) continue;
      const t = await ctx.readText(file);
      if (!t) {
        // Streamed (large) file: header-only detection, lower confidence.
        for await (const { text, line } of ctx.lines(file)) {
          HEADER.lastIndex = 0;
          const m = HEADER.exec(text);
          if (!m) continue;
          out.push(
            finding(
              file.relPath,
              line,
              m.index + 1,
              'pemKey',
              { keyType: m[1] ?? '' },
              scrubText(m[1] ?? ''),
              'critical',
              'medium',
              `pem:${line}`,
            ),
          );
        }
        continue;
      }
      if (!t.text.includes('PRIVATE KEY')) continue;
      const pem = findPemPrivateKeys(t.text);
      if (pem.length === 0) continue;

      if (SERVICE_ACCOUNT.test(t.text) && PRIVATE_KEY_FIELD.test(t.text)) {
        const idx = t.text.search(PRIVATE_KEY_FIELD);
        const pos = t.lines.position(idx);
        const project = /"project_id"\s*:\s*"([^"]{1,100})"/.exec(t.text)?.[1] ?? '?';
        const first = pem[0];
        out.push(
          finding(
            file.relPath,
            pos.line,
            pos.column,
            'serviceAccount',
            { project },
            first ? redactSecret(first.body) : scrubText('"private_key"'),
            'critical',
            'high',
            `sa:${project}`,
          ),
        );
        continue;
      }

      for (const hit of pem) {
        const pos = t.lines.position(hit.index);
        const keyType = hit.header.replace(/-----(?:BEGIN )?/g, '');
        out.push(
          finding(
            file.relPath,
            pos.line,
            pos.column,
            hit.encrypted ? 'encryptedPemKey' : 'pemKey',
            { keyType },
            joinRedacted([scrubText(keyType), redactSecret(hit.body)], ': '),
            hit.encrypted ? 'high' : 'critical',
            hit.encrypted ? 'medium' : 'high',
            `pem:${secretDigest(hit.body)}`,
          ),
        );
      }
    }
    return out;

    function finding(
      file: string,
      line: number,
      column: number,
      messageId: Msg,
      params: Record<string, string>,
      evidence: ReturnType<typeof scrubText>,
      severity: Severity,
      confidence: Confidence,
      key: string,
    ): FindingInput<Msg> {
      return {
        location: { file, line, column },
        messageId,
        params,
        evidence,
        severity,
        confidence: confidenceForPath(confidence, file),
        fingerprintKey: key,
      };
    }
  },
});
