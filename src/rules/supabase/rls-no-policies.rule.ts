import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import {
  confidenceFor,
  isRevokedFromApi,
  locate,
  qualifiedName,
  SUPABASE_REFERENCES,
  supabaseProjects,
} from './project.ts';

type Msg = 'noPolicies';

export const rlsNoPoliciesRule = defineRule<Msg>({
  meta: {
    id: 'supabase/rls-no-policies',
    family: 'supabase',
    defaultSeverity: 'low',
    cwe: [284, 1188],
    references: [...SUPABASE_REFERENCES],
    docs: {
      title: {
        en: 'Row Level Security enabled but no policies',
        ar: 'خاصية Row Level Security مفعّلة دون أي سياسات',
      },
      summary: {
        en: 'With RLS on and no permissive policy, the API returns no rows and rejects every write for anon and authenticated users. That is safe, but it is rarely intended, and the usual "fixes" are dangerous: disabling RLS, adding USING (true), or calling the database with the service_role key from the browser. Tables meant to be server-only should say so explicitly.',
        ar: 'عندما تكون RLS مفعّلة دون أي سياسة تسمح بالوصول، لا تُرجع الواجهة أي صفوف وترفض كل عمليات الكتابة للمستخدمين anon وauthenticated. هذا آمن لكنه نادرًا ما يكون مقصودًا، و"الحلول" المعتادة خطيرة: تعطيل RLS، أو إضافة USING (true)، أو استخدام مفتاح service_role من المتصفح. الجداول المخصّصة للخادم فقط يجب أن تُعلن ذلك صراحة.',
      },
      remediation: {
        text: {
          en: 'Add the policies the app needs, scoped to the row owner. If only your server (service_role) should touch the table, make that explicit by revoking API privileges. VibeGuard then treats it as intentional.',
          ar: 'أضف السياسات التي يحتاجها التطبيق مقصورةً على مالك الصف. وإن كان خادمك وحده (service_role) هو من يصل إلى الجدول، فاجعل ذلك صريحًا بسحب صلاحيات الواجهة، وعندها يعدّه VibeGuard أمرًا مقصودًا.',
        },
        codeLanguage: 'sql',
        vulnerable: `alter table public.notes enable row level security;
-- no policies: the app breaks, and the next "fix" is often: disable row level security`,
        fixed: `-- Option A: user-owned rows
create policy "Owners manage their notes" on public.notes
  for all to authenticated
  using ((select auth.uid()) = owner)
  with check ((select auth.uid()) = owner);

-- Option B: server-only table, deliberately unreachable from the Data API
revoke all on public.stripe_events from anon, authenticated;`,
      },
    },
    messages: {
      noPolicies: {
        en: 'Table {table} has Row Level Security enabled but no permissive policies: the Data API denies all access to it.',
        ar: 'الجدول {table} مفعّل عليه Row Level Security لكن دون سياسات تسمح بالوصول: واجهة البيانات تمنع أي وصول إليه.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const project of await supabaseProjects(ctx)) {
      for (const t of project.model.tables.values()) {
        if (!project.exposedSchemas.has(t.schema) || !t.rls || isRevokedFromApi(t)) continue;
        if ([...t.policies.values()].some((p) => p.permissive)) continue;
        const { location, evidence } = await locate(ctx, t.rlsLoc ?? t.created);
        out.push({
          location,
          messageId: 'noPolicies',
          params: { table: qualifiedName(t) },
          evidence,
          confidence: confidenceFor(project.model, t, 'high'),
          fingerprintKey: `table:${qualifiedName(t)}`,
        });
      }
    }
    return out;
  },
});
