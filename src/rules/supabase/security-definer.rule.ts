import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { locate, qualifiedName, SUPABASE_REFERENCES, supabaseProjects } from './project.ts';

/**
 * Views and functions in exposed schemas that run with their owner's privileges and so
 * bypass Row Level Security. These are lower confidence than the table rules: whether
 * they are dangerous depends on what they select and whether they check auth.uid().
 */

export const securityDefinerViewRule = defineRule<'view'>({
  meta: {
    id: 'supabase/security-definer-view',
    family: 'supabase',
    defaultSeverity: 'medium',
    cwe: [284, 269],
    references: [
      'https://supabase.com/docs/guides/database/database-advisors?lint=0010_security_definer_view',
      'https://www.postgresql.org/docs/current/sql-createview.html',
    ],
    docs: {
      title: { en: 'View bypasses Row Level Security', ar: 'عرض (View) يتجاوز Row Level Security' },
      summary: {
        en: 'By default a Postgres view runs with the privileges of its owner (usually postgres), so RLS on the underlying tables is not applied to the caller. A view in an exposed schema can therefore leak rows that the tables themselves protect, including rows from auth.users.',
        ar: 'افتراضيًا يُنفَّذ العرض (View) في Postgres بصلاحيات مالكه (postgres عادةً)، فلا تُطبَّق سياسات RLS الخاصة بالجداول الأساسية على المستدعي. لذا قد يكشف عرضٌ في مخطط مكشوف صفوفًا تحميها الجداول نفسها، بما فيها صفوف auth.users.',
      },
      remediation: {
        text: {
          en: "Create the view WITH (security_invoker = true) (Postgres 15+) so the caller's RLS applies, or move it to a non-exposed schema.",
          ar: 'أنشئ العرض مع الخيار WITH (security_invoker = true) (في Postgres 15 فأحدث) لتُطبَّق سياسات RLS الخاصة بالمستدعي، أو انقله إلى مخطط غير مكشوف.',
        },
        codeLanguage: 'sql',
        vulnerable: `create view public.user_emails as
  select id, email from auth.users;`,
        fixed: `create view public.my_profile
  with (security_invoker = true) as
  select id, full_name from public.profiles;`,
      },
    },
    messages: {
      view: {
        en: "View {view} runs with its owner's privileges (no security_invoker), so Row Level Security of the tables it reads is bypassed.",
        ar: 'العرض {view} يُنفَّذ بصلاحيات مالكه (دون security_invoker)، فتُتجاوز سياسات Row Level Security الخاصة بالجداول التي يقرأ منها.',
      },
    },
  },
  async detect(ctx) {
    const out: FindingInput<'view'>[] = [];
    for (const project of await supabaseProjects(ctx)) {
      for (const v of project.model.views.values()) {
        if (!project.exposedSchemas.has(v.schema) || v.securityInvoker) continue;
        const { location, evidence } = await locate(ctx, v.loc);
        out.push({
          location,
          messageId: 'view',
          params: { view: qualifiedName(v) },
          evidence,
          confidence: 'medium',
          fingerprintKey: `view:${qualifiedName(v)}`,
        });
      }
    }
    return out;
  },
});

export const securityDefinerFunctionRule = defineRule<'function' | 'functionAuthenticated'>({
  meta: {
    id: 'supabase/security-definer-function',
    family: 'supabase',
    defaultSeverity: 'medium',
    cwe: [269, 284],
    references: [
      ...SUPABASE_REFERENCES,
      'https://supabase.com/docs/guides/database/functions#security-definer-vs-invoker',
    ],
    docs: {
      title: {
        en: 'SECURITY DEFINER function callable through the API',
        ar: 'دالة SECURITY DEFINER يمكن استدعاؤها عبر الواجهة',
      },
      summary: {
        en: "Functions in an exposed schema can be called by API clients with supabase.rpc(). A SECURITY DEFINER function runs as its owner and ignores RLS. Unless it checks auth.uid() itself, any caller can make it act on anyone's data.",
        ar: 'الدوال الموجودة في مخطط مكشوف يمكن لعملاء الواجهة استدعاؤها عبر supabase.rpc(). ودالة SECURITY DEFINER تُنفَّذ بصلاحيات مالكها وتتجاهل RLS، فإن لم تتحقق هي نفسها من auth.uid() استطاع أي مستدعٍ جعلها تعمل على بيانات أي شخص.',
      },
      remediation: {
        text: {
          en: "Prefer SECURITY INVOKER. If definer rights are required, put the function in a non-exposed schema, or revoke EXECUTE from public, anon and authenticated and call it from the server. Inside the function, check auth.uid() and set search_path = ''.",
          ar: "فضّل SECURITY INVOKER. وإن احتجت صلاحيات المالك، فضع الدالة في مخطط غير مكشوف، أو اسحب صلاحية EXECUTE من public وanon وauthenticated واستدعها من الخادم. وداخل الدالة تحقّق من auth.uid() واضبط search_path = ''.",
        },
        codeLanguage: 'sql',
        vulnerable: `create function public.delete_user(uid uuid) returns void
language sql security definer as $$
  delete from auth.users where id = uid;
$$;`,
        fixed: `create function private.delete_user(uid uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if uid is distinct from (select auth.uid()) then
    raise exception 'not allowed';
  end if;
  delete from auth.users where id = uid;
end $$;
revoke execute on function private.delete_user(uuid) from public, anon, authenticated;`,
      },
    },
    messages: {
      function: {
        en: 'Function {function} is SECURITY DEFINER in an exposed schema and callable by anonymous clients via rpc(); it bypasses Row Level Security.',
        ar: 'الدالة {function} من نوع SECURITY DEFINER في مخطط مكشوف ويمكن للعملاء المجهولين استدعاؤها عبر rpc()؛ وهي تتجاوز Row Level Security.',
      },
      functionAuthenticated: {
        en: 'Function {function} is SECURITY DEFINER in an exposed schema and callable by any logged-in user via rpc(); it bypasses Row Level Security.',
        ar: 'الدالة {function} من نوع SECURITY DEFINER في مخطط مكشوف ويمكن لأي مستخدم مسجّل الدخول استدعاؤها عبر rpc()؛ وهي تتجاوز Row Level Security.',
      },
    },
  },
  async detect(ctx) {
    const out: FindingInput<'function' | 'functionAuthenticated'>[] = [];
    for (const project of await supabaseProjects(ctx)) {
      for (const f of project.model.functions.values()) {
        if (!project.exposedSchemas.has(f.schema) || !f.securityDefiner || f.returnsTrigger)
          continue;
        const anonCan = !(f.revoked.has('anon') && f.revoked.has('public'));
        const authCan = !(f.revoked.has('authenticated') && f.revoked.has('public'));
        if (!anonCan && !authCan) continue;
        const { location, evidence } = await locate(ctx, f.loc);
        out.push({
          location,
          messageId: anonCan ? 'function' : 'functionAuthenticated',
          params: { function: qualifiedName(f) },
          evidence,
          severity: anonCan ? 'medium' : 'low',
          confidence: 'low',
          fingerprintKey: `function:${qualifiedName(f)}`,
        });
      }
    }
    return out;
  },
});
