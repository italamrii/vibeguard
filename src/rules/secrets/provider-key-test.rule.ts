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

type Msg = 'testKey';

/**
 * Test-mode secret keys (Stripe `sk_test_` / `rk_test_`). Split from secrets/provider-key so
 * that tools which rank by rule (GitHub code scanning uses the rule's security-severity)
 * show them as low, not critical.
 */
export const providerKeyTestRule = defineRule<Msg>({
  meta: {
    id: 'secrets/provider-key-test',
    family: 'secrets',
    defaultSeverity: 'low',
    cwe: [798],
    references: [...SECRETS_REFERENCES, 'https://docs.stripe.com/keys#obtain-api-keys'],
    docs: {
      title: {
        en: 'Hardcoded test-mode API key',
        ar: 'مفتاح API لوضع الاختبار مكتوب مباشرة في الشيفرة',
      },
      summary: {
        en: 'A test-mode secret key (for example Stripe sk_test_…) is written in the code. It cannot move real money, but it grants full API access to your test account: test customers, webhooks, settings and logs. Test keys are often swapped for live keys in the same place, which is how live keys end up committed.',
        ar: 'مفتاح سري لوضع الاختبار (مثل sk_test_… الخاص بـ Stripe) مكتوب في الشيفرة. لا يستطيع تحريك أموال حقيقية، لكنه يمنح وصولًا كاملًا إلى حساب الاختبار عبر الواجهة: عملاء الاختبار وwebhooks والإعدادات والسجلات. وغالبًا ما يُستبدل مفتاح الاختبار بالمفتاح الحقيقي في المكان نفسه، وهكذا تنتهي المفاتيح الحقيقية مُودَعة في المستودع.',
      },
      remediation: {
        text: {
          en: 'Load test keys from the environment exactly like live keys, so that switching to live never means editing code. Roll the test key in the dashboard if the repository is shared or public.',
          ar: 'حمّل مفاتيح الاختبار من متغيرات البيئة تمامًا كالمفاتيح الحقيقية، حتى لا يتطلب الانتقال إلى الوضع الحقيقي تعديل الشيفرة. وجدّد مفتاح الاختبار من لوحة التحكم إن كان المستودع مشتركًا أو عامًا.',
        },
        codeLanguage: 'ts',
        vulnerable: `const stripe = new Stripe('sk_test_…'); // "only a test key", until it becomes sk_live_`,
        fixed: `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!); // sk_test_ locally, sk_live_ in production`,
      },
    },
    messages: {
      testKey: {
        en: '{provider} is hardcoded. Test-mode keys cannot move real money but still grant API access to your account’s test data and settings.',
        ar: 'المفتاح ({provider}) مكتوب مباشرة. مفاتيح وضع الاختبار لا تحرّك أموالًا حقيقية لكنها تمنح وصولًا إلى بيانات الاختبار وإعدادات حسابك.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files()) {
      if (!hardcodedScanApplies(file)) continue;
      for (const m of await secretsInFile(ctx, file)) {
        if (m.kind !== 'testKey') continue;
        out.push({
          location: {
            file: file.relPath,
            line: m.line,
            column: m.column,
            endLine: m.endLine,
            endColumn: m.endColumn,
          },
          messageId: 'testKey',
          params: { provider: m.provider },
          evidence: redactSecret(m.secret),
          confidence: confidenceForPath(m.confidence, file.relPath),
          fingerprintKey: `${m.patternId}:${secretDigest(m.secret)}`,
        });
      }
    }
    return out;
  },
});
