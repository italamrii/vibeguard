import { findEndpoints } from '../../analysis/routes.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { scrubText } from '../../core/redaction/redact.ts';
import {
  coveredByMiddleware,
  describe,
  ENDPOINT_REFERENCES,
  endpointContext,
  isAuthLike,
} from './common.ts';
import { firstLine } from './unauthenticated-data-access.rule.ts';

type Msg = 'noRateLimit';

const READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export const authRouteNoRateLimitRule = defineRule<Msg>({
  meta: {
    id: 'endpoints/auth-route-no-rate-limit',
    family: 'endpoints',
    defaultSeverity: 'medium',
    cwe: [307, 799],
    references: [
      ...ENDPOINT_REFERENCES,
      'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks',
    ],
    docs: {
      title: {
        en: 'Login / signup / reset endpoint without rate limiting',
        ar: 'نقطة تسجيل دخول أو تسجيل حساب أو استعادة كلمة مرور دون تحديد للمعدّل',
      },
      summary: {
        en: 'Custom credential endpoints (login, signup, password reset, OTP verification) are public by necessity. Without a rate limit, attackers can guess passwords and 6-digit codes, enumerate accounts, and run up your email/SMS bill. Endpoints that delegate to Supabase Auth or Firebase Auth are not reported, because those services rate-limit themselves.',
        ar: 'نقاط بيانات الاعتماد المخصّصة (تسجيل الدخول وإنشاء الحساب واستعادة كلمة المرور والتحقق من رموز OTP) عامة بطبيعتها. ودون تحديد للمعدّل يستطيع المهاجمون تخمين كلمات المرور والرموز المكوّنة من 6 أرقام، وحصر الحسابات، ورفع فاتورة البريد أو الرسائل النصية. لا تُبلَّغ النقاط التي تفوّض العملية إلى Supabase Auth أو Firebase Auth لأن هذه الخدمات تحدّ المعدّل بنفسها.',
      },
      remediation: {
        text: {
          en: 'Limit by IP and by account (e.g. 5 attempts per 15 minutes) with a shared store (Redis/Upstash), not process memory, on serverless platforms. Return the same response for unknown accounts, and add exponential backoff or CAPTCHA after repeated failures.',
          ar: 'حدّد المعدّل حسب عنوان IP وحسب الحساب (مثل 5 محاولات كل 15 دقيقة) باستخدام مخزن مشترك (Redis/Upstash) لا ذاكرة العملية، خاصة على المنصات عديمة الخادم. أعد الاستجابة نفسها للحسابات غير الموجودة، وأضف تأخيرًا متزايدًا أو CAPTCHA بعد تكرار الفشل.',
        },
        codeLanguage: 'ts',
        vulnerable: `app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) return res.sendStatus(401);
  res.json({ token: signToken(user) });
});`,
        fixed: `import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7' });

app.post('/api/login', loginLimiter, async (req, res) => {
  // … same handler …
});`,
      },
    },
    messages: {
      noRateLimit: {
        en: '{endpoint} handles credentials and has no rate limiting.',
        ar: 'النقطة {endpoint} تتعامل مع بيانات الاعتماد دون أي تحديد للمعدّل.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    const ec = await endpointContext(ctx);
    for (const ep of await findEndpoints(ctx)) {
      if (!isAuthLike(ep) || READ_ONLY_METHODS.has(ep.method)) continue;
      const a = await ec.signals.analyse(ep.file, ep.sf, [
        ...ep.handlers,
        ...ep.middleware,
        ...ep.inherited,
      ]);
      if (a.rateLimit.length > 0 || a.managedAuth) continue;
      if (coveredByMiddleware(ec, ep, (m) => m.rateLimits)) continue;
      const pos = nodePosition(ep.sf, ep.node);
      out.push({
        location: { file: ep.file, line: pos.line, column: pos.column },
        messageId: 'noRateLimit',
        params: { endpoint: describe(ep) },
        evidence: scrubText(firstLine(ep.node.getText(ep.sf)), { maxLength: 120 }),
        confidence: 'medium',
        fingerprintKey: `${ep.method} ${ep.path}`,
      });
    }
    return out;
  },
});
