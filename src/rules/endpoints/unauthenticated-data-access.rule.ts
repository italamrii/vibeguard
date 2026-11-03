import { findEndpoints } from '../../analysis/routes.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { scrubText } from '../../core/redaction/redact.ts';
import {
  coveredByMiddleware,
  describe,
  ENDPOINT_REFERENCES,
  endpointContext,
  isAuthLike,
  isPublicUtility,
  isSessionTermination,
} from './common.ts';
import type { Sink } from './signals.ts';

type Msg = 'privilegedMutation' | 'mutation' | 'rlsGuardedMutation' | 'privilegedRead' | 'read';

interface Verdict {
  readonly messageId: Msg;
  readonly severity: Severity;
  readonly confidence: Confidence;
}

/** Exported for tests. Picks the most dangerous sink an endpoint reaches. */
export function verdictFor(sinks: readonly Sink[]): { verdict: Verdict; sink: Sink } | undefined {
  const rank: [(s: Sink) => boolean, Verdict][] = [
    [
      (s) => s.kind === 'mutation' && s.privilege === 'privileged',
      { messageId: 'privilegedMutation', severity: 'critical', confidence: 'high' },
    ],
    [
      (s) => s.kind === 'mutation' && s.privilege === 'direct',
      { messageId: 'mutation', severity: 'high', confidence: 'high' },
    ],
    [
      (s) => s.kind === 'read' && s.privilege === 'privileged',
      { messageId: 'privilegedRead', severity: 'high', confidence: 'medium' },
    ],
    [
      (s) => s.kind === 'read' && s.privilege === 'direct',
      { messageId: 'read', severity: 'medium', confidence: 'low' },
    ],
    [
      (s) => s.kind === 'mutation' && s.privilege === 'user-scoped',
      { messageId: 'rlsGuardedMutation', severity: 'low', confidence: 'low' },
    ],
  ];
  for (const [match, verdict] of rank) {
    const sink = sinks.find(match);
    if (sink) return { verdict, sink };
  }
  return undefined; // reads through a user-scoped Supabase client: RLS decides, by design
}

export const unauthenticatedDataAccessRule = defineRule<Msg>({
  meta: {
    id: 'endpoints/unauthenticated-data-access',
    family: 'endpoints',
    defaultSeverity: 'high',
    cwe: [306, 862, 285],
    references: [
      ...ENDPOINT_REFERENCES,
      'https://nextjs.org/docs/app/guides/authentication',
      'https://nextjs.org/docs/app/guides/data-security',
    ],
    docs: {
      title: {
        en: 'Endpoint reads or changes data without an authentication check',
        ar: 'نقطة نهاية تقرأ البيانات أو تغيّرها دون التحقق من هوية المستخدم',
      },
      summary: {
        en: 'Route handlers, API routes, server actions and Express/Fastify routes are public URLs: anyone can call them directly, without your UI. This one reaches the database (or a privileged SDK) and VibeGuard found no authentication check in the handler, its middleware, the helpers it calls, or a Next.js middleware that covers it. Hiding a button in the UI is not access control. Server actions in particular are POST endpoints that anyone can invoke.',
        ar: 'معالجات المسارات وواجهات API وserver actions ومسارات Express/Fastify كلها عناوين URL عامة: يستطيع أي شخص استدعاءها مباشرة دون المرور بواجهتك. هذه النقطة تصل إلى قاعدة البيانات (أو إلى SDK ذي صلاحيات)، ولم يجد VibeGuard أي تحقق من الهوية في المعالج أو في الوسيط (middleware) المرتبط به أو في الدوال المساعدة التي يستدعيها أو في middleware خاص بـ Next.js يغطيه. إخفاء زر في الواجهة ليس تحكمًا في الوصول، وserver actions تحديدًا نقاط POST يستطيع أي شخص استدعاءها.',
      },
      remediation: {
        text: {
          en: 'Authenticate at the start of every handler (or in middleware that provably covers the route), then authorise: check that the user may act on this specific record. Return 401/403 before touching data. Never use a service-role / admin client in a handler that has not verified the caller.',
          ar: 'تحقّق من الهوية في بداية كل معالج (أو في middleware يغطي المسار بشكل مؤكد)، ثم تحقّق من الصلاحية: هل يحق لهذا المستخدم التصرف في هذا السجل تحديدًا؟ أعد 401 أو 403 قبل لمس البيانات. ولا تستخدم أبدًا عميل service-role أو admin في معالج لم يتحقق من هوية المستدعي.',
        },
        codeLanguage: 'ts',
        vulnerable: `// app/api/notes/[id]/route.ts
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await supabaseAdmin.from('notes').delete().eq('id', params.id); // anyone can delete any note
  return Response.json({ ok: true });
}`,
        fixed: `export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const supabase = await createClient(); // cookie-based, anon key: RLS applies
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const { error } = await supabase.from('notes').delete().eq('id', params.id).eq('owner', user.id);
  if (error) return new Response('Forbidden', { status: 403 });
  return Response.json({ ok: true });
}`,
      },
    },
    messages: {
      privilegedMutation: {
        en: '{endpoint} modifies data with a privileged client ({api}) and has no authentication check: anyone can call it.',
        ar: 'النقطة {endpoint} تعدّل البيانات بعميل ذي صلاحيات ({api}) دون أي تحقق من الهوية: يستطيع أي شخص استدعاءها.',
      },
      mutation: {
        en: '{endpoint} modifies data ({api}) and has no authentication check.',
        ar: 'النقطة {endpoint} تعدّل البيانات ({api}) دون أي تحقق من الهوية.',
      },
      privilegedRead: {
        en: '{endpoint} reads data with a privileged client ({api}), bypassing Row Level Security, and has no authentication check.',
        ar: 'النقطة {endpoint} تقرأ البيانات بعميل ذي صلاحيات ({api}) متجاوزةً Row Level Security، دون أي تحقق من الهوية.',
      },
      read: {
        en: '{endpoint} reads data ({api}) with no authentication check. Confirm the data is meant to be public.',
        ar: 'النقطة {endpoint} تقرأ البيانات ({api}) دون أي تحقق من الهوية. تأكّد من أن هذه البيانات مقصود أن تكون عامة.',
      },
      rlsGuardedMutation: {
        en: '{endpoint} modifies data ({api}) without checking the user; only Row Level Security protects it. Verify the policies, and prefer an explicit check.',
        ar: 'النقطة {endpoint} تعدّل البيانات ({api}) دون التحقق من المستخدم؛ لا يحميها سوى Row Level Security. تحقّق من السياسات، والأفضل إضافة تحقق صريح.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    const ec = await endpointContext(ctx);
    for (const ep of await findEndpoints(ctx)) {
      if (isAuthLike(ep) || isPublicUtility(ep) || isSessionTermination(ep)) continue;
      const a = await ec.signals.analyse(ep.file, ep.sf, [
        ...ep.handlers,
        ...ep.middleware,
        ...ep.inherited,
      ]);
      if (a.auth.length > 0) continue;
      if (coveredByMiddleware(ec, ep, (m) => m.enforcesAuth)) continue;
      const v = verdictFor(a.sinks);
      if (!v) continue;
      const pos = nodePosition(ep.sf, ep.node);
      out.push({
        location: { file: ep.file, line: pos.line, column: pos.column },
        messageId: v.verdict.messageId,
        params: { endpoint: describe(ep), api: v.sink.api },
        evidence: scrubText(firstLine(ep.node.getText(ep.sf)), { maxLength: 120 }),
        severity: v.verdict.severity,
        confidence: v.verdict.confidence,
        fingerprintKey: `${ep.method} ${ep.path}`,
      });
    }
    return out;
  },
});

export function firstLine(s: string): string {
  return s.split('\n')[0] ?? s;
}
