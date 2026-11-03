import { findEndpoints } from '../../analysis/routes.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { scrubText } from '../../core/redaction/redact.ts';
import { describe, endpointContext, isWebhook } from './common.ts';
import { firstLine } from './unauthenticated-data-access.rule.ts';

type Msg = 'unsigned' | 'unsignedWrites';

export const webhookWithoutSignatureRule = defineRule<Msg>({
  meta: {
    id: 'endpoints/webhook-without-signature',
    family: 'endpoints',
    defaultSeverity: 'high',
    cwe: [345, 347, 306],
    references: [
      'https://docs.stripe.com/webhooks#verify-events',
      'https://docs.svix.com/receiving/verifying-payloads/how',
      'https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries',
    ],
    docs: {
      title: {
        en: 'Webhook endpoint does not verify the sender',
        ar: 'نقطة webhook لا تتحقق من هوية المُرسِل',
      },
      summary: {
        en: 'Webhook URLs are public and easy to guess (/api/webhooks/stripe). Without verifying the provider\'s signature (or a shared secret), anyone can POST a fake "payment succeeded" or "user created" event and your handler will act on it. Session-based auth does not apply here: the sender must be authenticated by signature.',
        ar: 'عناوين webhook عامة ويسهل تخمينها (/api/webhooks/stripe). وبدون التحقق من توقيع المزوّد (أو من سرّ مشترك) يستطيع أي شخص إرسال حدث مزيّف مثل "تمت عملية الدفع" أو "أُنشئ مستخدم" فيتصرف المعالج بناءً عليه. التحقق عبر الجلسات لا ينطبق هنا: يجب التحقق من المُرسِل عبر التوقيع.',
      },
      remediation: {
        text: {
          en: 'Verify the signature over the raw request body with the provider SDK (stripe.webhooks.constructEvent, svix Webhook.verify, @octokit/webhooks verify) or an HMAC with crypto.timingSafeEqual, and reject unsigned or stale events before touching data. If a gateway verifies signatures for you, suppress this finding with that reason.',
          ar: 'تحقّق من التوقيع على جسم الطلب الخام باستخدام SDK المزوّد (stripe.webhooks.constructEvent أو Webhook.verify من svix أو verify من @octokit/webhooks) أو عبر HMAC مع crypto.timingSafeEqual، وارفض الأحداث غير الموقّعة أو القديمة قبل لمس البيانات. وإن كانت بوابة ما تتحقق من التواقيع نيابةً عنك، فاكتم هذه النتيجة مع ذكر ذلك السبب.',
        },
        codeLanguage: 'ts',
        vulnerable: `export async function POST(req: Request) {
  const event = await req.json(); // anyone can send this
  if (event.type === 'checkout.session.completed') await markPaid(event.data.object.id);
}`,
        fixed: `export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(
    await req.text(),                       // raw body, not JSON-parsed
    req.headers.get('stripe-signature')!,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );                                         // throws on a bad signature
  if (event.type === 'checkout.session.completed') await markPaid(event.data.object.id);
}`,
      },
    },
    messages: {
      unsigned: {
        en: '{endpoint} looks like a webhook receiver but verifies no signature or shared secret.',
        ar: 'تبدو النقطة {endpoint} مستقبِلًا لـ webhook لكنها لا تتحقق من أي توقيع أو سرّ مشترك.',
      },
      unsignedWrites: {
        en: "{endpoint} is a webhook receiver that modifies data ({api}) without verifying the sender's signature: anyone can forge events.",
        ar: 'النقطة {endpoint} مستقبِل webhook يعدّل البيانات ({api}) دون التحقق من توقيع المُرسِل: يستطيع أي شخص تزوير الأحداث.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    const ec = await endpointContext(ctx);
    for (const ep of await findEndpoints(ctx)) {
      if (!isWebhook(ep) || ep.method === 'GET' || ep.method === 'HEAD') continue;
      const a = await ec.signals.analyse(ep.file, ep.sf, [
        ...ep.handlers,
        ...ep.middleware,
        ...ep.inherited,
      ]);
      if (a.signature) continue;
      const write = a.sinks.find((s) => s.kind === 'mutation' || s.kind === 'outbound');
      const pos = nodePosition(ep.sf, ep.node);
      out.push({
        location: { file: ep.file, line: pos.line, column: pos.column },
        messageId: write ? 'unsignedWrites' : 'unsigned',
        params: { endpoint: describe(ep), api: write?.api ?? '' },
        evidence: scrubText(firstLine(ep.node.getText(ep.sf)), { maxLength: 120 }),
        severity: write ? 'high' : 'medium',
        // Signatures can be verified upstream (API gateway, edge middleware) where we cannot see.
        confidence: 'medium',
        fingerprintKey: `${ep.method} ${ep.path}`,
      });
    }
    return out;
  },
});
