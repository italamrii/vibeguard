import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { redactSecret } from '../../core/redaction/redact.ts';
import {
  confidenceForPath,
  hardcodedScanApplies,
  secretDigest,
  secretsInFile,
  SECRETS_REFERENCES,
} from './common.ts';

type Msg = 'hardcoded' | 'keyId' | 'dbUrl';

export const providerKeyRule = defineRule<Msg>({
  meta: {
    id: 'secrets/provider-key',
    family: 'secrets',
    defaultSeverity: 'critical',
    cwe: [798, 312],
    references: [
      ...SECRETS_REFERENCES,
      'https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning',
    ],
    docs: {
      title: {
        en: 'Hardcoded provider credential',
        ar: 'بيانات اعتماد مزوّد خدمة مكتوبة مباشرة في الشيفرة',
      },
      summary: {
        en: 'A credential for a third-party service (Stripe, OpenAI, AWS, Supabase, GitHub, a database, …) is written directly in a file that is, or will be, committed. Anyone with read access to the repository, its history, a fork, a CI log or a client bundle can use it. Deleting the line later does not remove it from git history.',
        ar: 'بيانات اعتماد لخدمة خارجية (Stripe أو OpenAI أو AWS أو Supabase أو GitHub أو قاعدة بيانات…) مكتوبة مباشرة في ملف مُودَع أو سيُودَع في المستودع. يستطيع استخدامها كل من يملك صلاحية قراءة المستودع أو سجله أو نسخة منه أو سجلات CI أو حزمة الواجهة. حذف السطر لاحقًا لا يزيله من سجل git.',
      },
      remediation: {
        text: {
          en: '1) Revoke and rotate the credential in the provider dashboard now; assume it is compromised. 2) Load it from an environment variable on the server only (never with a NEXT_PUBLIC_/VITE_ prefix). 3) Keep real values in a gitignored .env.local or your host’s secret manager, and commit only a .env.example with placeholders. 4) If it was pushed, purge it from history (git filter-repo) after rotating.',
          ar: '١) ألغِ بيانات الاعتماد وأنشئ بديلًا لها فورًا من لوحة المزوّد، وافترض أنها مُسرَّبة. ٢) حمّلها من متغير بيئة على الخادم فقط (دون البادئة NEXT_PUBLIC_ أو VITE_). ٣) احفظ القيم الحقيقية في ملف .env.local مُستثنى من git أو في مدير الأسرار لدى الاستضافة، وأودِع فقط ملف .env.example بقيم شكلية. ٤) إن كانت قد رُفعت فعلًا، فامسحها من السجل (git filter-repo) بعد تدويرها.',
        },
        codeLanguage: 'ts',
        vulnerable: `// src/lib/stripe.ts
import Stripe from 'stripe';
export const stripe = new Stripe('sk_live_…'); // real key committed to git`,
        fixed: `// src/lib/stripe.ts (server-only module)
import 'server-only';
import Stripe from 'stripe';

const key = process.env.STRIPE_SECRET_KEY;
if (!key) throw new Error('STRIPE_SECRET_KEY is not set');
export const stripe = new Stripe(key);

// .env.local (gitignored):   STRIPE_SECRET_KEY=<from the Stripe dashboard>
// .env.example (committed):  STRIPE_SECRET_KEY=`,
      },
    },
    messages: {
      hardcoded: {
        en: '{provider} is hardcoded in this file.',
        ar: 'المفتاح ({provider}) مكتوب مباشرة في هذا الملف.',
      },
      keyId: {
        en: '{provider} is hardcoded. On its own it is an identifier, but its secret key is usually nearby; check this file and its history.',
        ar: 'المعرّف ({provider}) مكتوب مباشرة. هو وحده معرّف فقط، لكن المفتاح السري المرتبط به يكون عادةً قريبًا؛ افحص هذا الملف وسجله.',
      },
      dbUrl: {
        en: 'A database connection string with an embedded password is hardcoded.',
        ar: 'سلسلة اتصال بقاعدة بيانات تتضمن كلمة مرور مكتوبة مباشرة.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files()) {
      if (!hardcodedScanApplies(file)) continue;
      for (const m of await secretsInFile(ctx, file)) {
        // Test-mode keys are reported by secrets/provider-key-test (its own, low, severity).
        if (m.kind === 'publicByContext' || m.kind === 'testKey') continue;
        const messageId: Msg =
          m.kind === 'keyId' ? 'keyId' : m.kind === 'dbUrl' ? 'dbUrl' : 'hardcoded';
        out.push({
          location: {
            file: file.relPath,
            line: m.line,
            column: m.column,
            endLine: m.endLine,
            endColumn: m.endColumn,
          },
          messageId,
          params: { provider: m.provider },
          evidence: redactSecret(m.secret),
          severity: m.severity,
          confidence: confidenceForPath(m.confidence, file.relPath),
          fingerprintKey: `${m.patternId}:${secretDigest(m.secret)}`,
        });
      }
    }
    return out;
  },
});
