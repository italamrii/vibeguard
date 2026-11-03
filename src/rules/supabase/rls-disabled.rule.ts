import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import {
  isRevokedFromApi,
  isUncertain,
  locate,
  qualifiedName,
  SUPABASE_REFERENCES,
  supabaseProjects,
} from './project.ts';

type Msg = 'disabled' | 'disabledWithPolicies' | 'unverified';

export const rlsDisabledRule = defineRule<Msg>({
  meta: {
    id: 'supabase/rls-disabled',
    family: 'supabase',
    defaultSeverity: 'critical',
    cwe: [284, 862],
    references: [...SUPABASE_REFERENCES],
    docs: {
      title: {
        en: 'Row Level Security is not enabled on an exposed table',
        ar: 'خاصية Row Level Security غير مفعّلة على جدول مكشوف',
      },
      summary: {
        en: 'Tables in schemas exposed by the Supabase Data API (public by default) can be queried by anyone holding your anon key, and that key ships in every browser bundle. Without Row Level Security, any visitor can read, modify and delete every row of this table with a single HTTP request. Policies on a table do nothing while RLS is disabled.',
        ar: 'الجداول الموجودة في المخططات التي تكشفها واجهة Supabase Data API (المخطط public افتراضيًا) يستطيع الاستعلام عنها كل من يملك مفتاح anon، وهذا المفتاح موجود في حزمة كل متصفح. بدون Row Level Security يستطيع أي زائر قراءة كل صفوف الجدول وتعديلها وحذفها بطلب HTTP واحد. والسياسات المعرّفة على الجدول لا تعمل ما دامت RLS معطّلة.',
      },
      remediation: {
        text: {
          en: 'Enable RLS in a new migration and add policies that scope rows to their owner. If the table must never be reachable from the API, also revoke privileges from anon and authenticated, or move it to a non-exposed schema. Do not "fix" access errors by disabling RLS.',
          ar: 'فعّل RLS في ملف ترحيل جديد وأضف سياسات تقصر الوصول إلى الصفوف على مالكها. وإن كان الجدول يجب ألا يُصل إليه عبر الواجهة أبدًا، فاسحب الصلاحيات من الدورين anon وauthenticated أو انقله إلى مخطط غير مكشوف. لا تحلّ أخطاء الوصول بتعطيل RLS.',
        },
        codeLanguage: 'sql',
        vulnerable: `create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  stripe_customer_id text
);
-- (no "enable row level security": anyone with the anon key can read and edit all profiles)`,
        fixed: `alter table public.profiles enable row level security;

create policy "Users read their own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);

create policy "Users update their own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);`,
      },
    },
    messages: {
      disabled: {
        en: 'Table {table} is in an exposed schema and Row Level Security is not enabled after all migrations.',
        ar: 'الجدول {table} في مخطط مكشوف، وخاصية Row Level Security غير مفعّلة بعد تطبيق جميع ملفات الترحيل.',
      },
      disabledWithPolicies: {
        en: 'Table {table} has {count} policy(ies), but Row Level Security is disabled, so none of them is enforced.',
        ar: 'للجدول {table} عدد {count} من السياسات، لكن Row Level Security معطّلة، لذا لا تُطبَّق أيٌّ منها.',
      },
      unverified: {
        en: 'Table {table} has no Row Level Security in the migrations VibeGuard could parse, but a statement touching it could not be analysed. Verify manually.',
        ar: 'الجدول {table} بلا Row Level Security في ملفات الترحيل التي أمكن تحليلها، لكن تعذّر تحليل جملة تتعلق به. تحقّق يدويًا.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const project of await supabaseProjects(ctx)) {
      for (const t of project.model.tables.values()) {
        if (!project.exposedSchemas.has(t.schema) || t.rls || isRevokedFromApi(t)) continue;
        const uncertain = isUncertain(project.model, t);
        const messageId: Msg = uncertain
          ? 'unverified'
          : t.policies.size > 0
            ? 'disabledWithPolicies'
            : 'disabled';
        // Point at the statement that turned RLS off, or at the CREATE TABLE if it was never on.
        const { location, evidence } = await locate(ctx, t.rlsLoc ?? t.created);
        out.push({
          location,
          messageId,
          params: { table: qualifiedName(t), count: t.policies.size },
          evidence,
          confidence: uncertain ? 'low' : 'high',
          fingerprintKey: `table:${qualifiedName(t)}`,
        });
      }
    }
    return out;
  },
});
