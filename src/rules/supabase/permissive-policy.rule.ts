import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { reachOf } from './policy-expr.ts';
import {
  confidenceFor,
  INTAKE_TABLE,
  locate,
  PUBLIC_LOOKUP_TABLE,
  qualifiedName,
  SENSITIVE_TABLE,
  SUPABASE_REFERENCES,
  supabaseProjects,
} from './project.ts';
import type { PolicyState } from './schema-model.ts';

type Msg =
  | 'writeAnyone'
  | 'writeAnyAuthenticated'
  | 'insertAnyone'
  | 'insertAnyAuthenticated'
  | 'readAnyone'
  | 'readAnyAuthenticated';

type Audience = 'anyone' | 'anyAuthenticated';
type TableKind = 'sensitive' | 'lookup' | 'intake' | 'other';

const API_ROLES = new Set(['public', 'anon', 'authenticated']);

/** Who a policy effectively admits to every row, or undefined when it is row-scoped. */
export function audienceOf(p: PolicyState): Audience | undefined {
  if (!p.permissive) return undefined; // restrictive policies only narrow access
  const roles = p.roles.filter((r) => API_ROLES.has(r));
  if (roles.length === 0) return undefined; // e.g. TO service_role
  const cond = p.command === 'insert' ? p.withCheck : p.qual;
  const reach = reachOf(cond);
  if (reach === undefined || reach === 'scoped') return undefined;
  const anonIncluded = roles.includes('public') || roles.includes('anon');
  // auth.uid() IS NOT NULL is false for anon requests: it means "any logged-in user".
  return reach === 'true' && anonIncluded ? 'anyone' : 'anyAuthenticated';
}

function tableKind(name: string): TableKind {
  if (INTAKE_TABLE.test(name)) return 'intake';
  if (PUBLIC_LOOKUP_TABLE.test(name)) return 'lookup';
  if (SENSITIVE_TABLE.test(name)) return 'sensitive';
  return 'other';
}

interface Verdict {
  readonly messageId: Msg;
  readonly severity: Severity;
  readonly confidence: Confidence;
}

/** Severity matrix (documented in docs/rules/supabase/permissive-policy.md). Exported for tests. */
export function verdict(
  command: PolicyState['command'],
  audience: Audience,
  table: string,
): Verdict | undefined {
  const kind = tableKind(table);
  if (command === 'insert') {
    if (kind === 'intake') {
      return audience === 'anyone'
        ? { messageId: 'insertAnyone', severity: 'medium', confidence: 'medium' }
        : { messageId: 'insertAnyAuthenticated', severity: 'low', confidence: 'medium' };
    }
    return audience === 'anyone'
      ? { messageId: 'insertAnyone', severity: 'high', confidence: 'high' }
      : { messageId: 'insertAnyAuthenticated', severity: 'medium', confidence: 'medium' };
  }
  if (command === 'select') {
    if (audience === 'anyone') {
      if (kind === 'lookup') return { messageId: 'readAnyone', severity: 'low', confidence: 'low' };
      if (kind === 'sensitive')
        return { messageId: 'readAnyone', severity: 'high', confidence: 'medium' };
      return { messageId: 'readAnyone', severity: 'medium', confidence: 'medium' };
    }
    if (kind === 'lookup') return undefined;
    if (kind === 'sensitive')
      return { messageId: 'readAnyAuthenticated', severity: 'medium', confidence: 'medium' };
    return { messageId: 'readAnyAuthenticated', severity: 'low', confidence: 'low' };
  }
  // update / delete / all
  return audience === 'anyone'
    ? { messageId: 'writeAnyone', severity: 'critical', confidence: 'high' }
    : { messageId: 'writeAnyAuthenticated', severity: 'high', confidence: 'high' };
}

export const permissivePolicyRule = defineRule<Msg>({
  meta: {
    id: 'supabase/permissive-policy',
    family: 'supabase',
    defaultSeverity: 'high',
    cwe: [284, 639],
    references: [
      ...SUPABASE_REFERENCES,
      'https://supabase.com/docs/guides/database/postgres/row-level-security#policies',
    ],
    docs: {
      title: {
        en: 'Overly permissive Row Level Security policy',
        ar: 'سياسة Row Level Security متساهلة أكثر من اللازم',
      },
      summary: {
        en: "RLS is on, but a policy admits every row: USING (true) / WITH CHECK (true), or a condition that only checks the caller is logged in (auth.uid() IS NOT NULL, auth.role() = 'authenticated'). For UPDATE/DELETE that lets any visitor or any user edit and wipe everyone's data. For INSERT, anyone can create rows on behalf of others. For SELECT on personal data, everything is readable. Read-only access to obvious reference data (countries, plans, tags) is reported at low severity so you can confirm it is intentional.",
        ar: "خاصية RLS مفعّلة، لكن إحدى السياسات تسمح بكل الصفوف: USING (true) أو WITH CHECK (true)، أو شرط يكتفي بالتحقق من أن المستخدم مسجّل الدخول (auth.uid() IS NOT NULL أو auth.role() = 'authenticated'). في UPDATE وDELETE يستطيع أي زائر أو أي مستخدم تعديل بيانات الجميع ومسحها. وفي INSERT يستطيع أي شخص إنشاء صفوف باسم غيره. وفي SELECT على بيانات شخصية تصبح كلها مقروءة. أما القراءة فقط لبيانات مرجعية واضحة (الدول والخطط والوسوم) فتُبلَّغ بخطورة منخفضة لتتأكد من أنها مقصودة.",
      },
      remediation: {
        text: {
          en: 'Scope every write policy to the row owner, in both USING (which rows) and WITH CHECK (what rows may become). Use separate policies per command. Prefer "TO authenticated" plus an ownership check over "TO anon/public".',
          ar: 'اقصر كل سياسة كتابة على مالك الصف، في USING (أي الصفوف) وفي WITH CHECK (ما يمكن أن تصبح عليه الصفوف). استخدم سياسة منفصلة لكل أمر. وفضّل "TO authenticated" مع شرط الملكية على "TO anon/public".',
        },
        codeLanguage: 'sql',
        vulnerable: `create policy "Enable update for users" on public.orders
  for update to authenticated
  using (true) with check (true);  -- any user can edit any order`,
        fixed: `create policy "Users update their own orders" on public.orders
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);`,
      },
    },
    messages: {
      writeAnyone: {
        en: 'Policy "{policy}" lets anyone, including anonymous visitors, {command} every row of {table}.',
        ar: 'السياسة "{policy}" تسمح لأي شخص، بما في ذلك الزوار المجهولون، بتنفيذ {command} على كل صفوف {table}.',
      },
      writeAnyAuthenticated: {
        en: 'Policy "{policy}" lets any logged-in user {command} every row of {table}, not just their own.',
        ar: 'السياسة "{policy}" تسمح لأي مستخدم مسجّل الدخول بتنفيذ {command} على كل صفوف {table}، لا على صفوفه فقط.',
      },
      insertAnyone: {
        en: 'Policy "{policy}" lets anyone, including anonymous visitors, insert arbitrary rows into {table}.',
        ar: 'السياسة "{policy}" تسمح لأي شخص، بما في ذلك الزوار المجهولون، بإدراج صفوف عشوائية في {table}.',
      },
      insertAnyAuthenticated: {
        en: 'Policy "{policy}" lets any logged-in user insert rows into {table} with any owner or values (WITH CHECK does not tie rows to the caller).',
        ar: 'السياسة "{policy}" تسمح لأي مستخدم مسجّل الدخول بإدراج صفوف في {table} بأي مالك أو قيم (لأن WITH CHECK لا يربط الصفوف بالمستخدم).',
      },
      readAnyone: {
        en: 'Policy "{policy}" makes every row of {table} readable by anyone, including anonymous visitors.',
        ar: 'السياسة "{policy}" تجعل كل صفوف {table} مقروءة لأي شخص، بما في ذلك الزوار المجهولون.',
      },
      readAnyAuthenticated: {
        en: 'Policy "{policy}" makes every row of {table} readable by any logged-in user.',
        ar: 'السياسة "{policy}" تجعل كل صفوف {table} مقروءة لأي مستخدم مسجّل الدخول.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const project of await supabaseProjects(ctx)) {
      for (const t of project.model.tables.values()) {
        // With RLS off, policies are not enforced; supabase/rls-disabled reports that.
        if (!project.exposedSchemas.has(t.schema) || !t.rls) continue;
        for (const p of t.policies.values()) {
          const audience = audienceOf(p);
          const v = audience ? verdict(p.command, audience, t.name) : undefined;
          if (!v) continue;
          const { location, evidence } = await locate(ctx, p.loc);
          out.push({
            location,
            messageId: v.messageId,
            params: { policy: p.name, table: qualifiedName(t), command: p.command.toUpperCase() },
            evidence,
            severity: v.severity,
            confidence: confidenceFor(project.model, t, v.confidence),
            fingerprintKey: `policy:${qualifiedName(t)}:${p.name}`,
          });
        }
      }
    }
    return out;
  },
});
