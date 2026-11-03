import path from 'node:path';
import ts from 'typescript';
import { dottedName, walk } from '../../analysis/ast-utils.ts';
import { classifyRuntime } from '../../analysis/runtime.ts';
import { CODE_KINDS } from '../../core/discovery/file-kind.ts';
import type { FileRecord } from '../../core/discovery/walker.ts';
import { defineRule, type RuleContext } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { scrubText } from '../../core/redaction/redact.ts';
import { publicPrefixOf } from '../secrets/client-exposed-env.rule.ts';
import { findSecrets } from '../secrets/patterns.ts';

type Msg = 'envInClient' | 'adminModuleImported';

/** Env var names that hold the service_role / secret key. */
const SERVICE_KEY_NAME = /SERVICE[_-]?ROLE|^SUPABASE_SECRET|^SB_SECRET/i;
const ENV_REF = /^(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)$/;
const CODE_EXTENSIONS = [
  '',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '/index.ts',
  '/index.tsx',
  '/index.js',
  '/index.jsx',
];

/** A module that creates or holds a service-role client: references the key by name, or embeds it. */
async function isAdminModule(
  ctx: RuleContext,
  file: FileRecord,
  memo: Map<string, Promise<boolean>>,
): Promise<boolean> {
  let p = memo.get(file.relPath);
  if (!p) {
    p = (async () => {
      const t = await ctx.readText(file);
      if (!t) return false;
      if (/SERVICE[_-]?ROLE|SUPABASE_SECRET|SB_SECRET/i.test(t.text)) return true;
      return findSecrets(t.text).some(
        (m) => m.patternId === 'supabase-service-role-jwt' || m.patternId === 'supabase-secret-key',
      );
    })();
    memo.set(file.relPath, p);
  }
  return p;
}

/** Resolve `./x`, `../x`, `@/x`, `~/x` to a scanned file. Bare package specifiers are not followed. */
export function resolveImport(
  ctx: RuleContext,
  fromRel: string,
  spec: string,
): FileRecord | undefined {
  const bases: string[] = [];
  if (spec.startsWith('./') || spec.startsWith('../')) {
    bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec)));
  } else if (spec.startsWith('@/') || spec.startsWith('~/')) {
    const rest = spec.slice(2);
    bases.push(`src/${rest}`, rest);
  } else {
    return undefined;
  }
  for (const base of bases) {
    for (const ext of CODE_EXTENSIONS) {
      const f = ctx.file(`${base}${ext}`);
      if (f && CODE_KINDS.includes(f.kind)) return f;
    }
  }
  return undefined;
}

const SERVER_DATA_FUNCTIONS = new Set(['getServerSideProps', 'getStaticProps', 'getStaticPaths']);

/** `export async function getServerSideProps() {}` or `export const getStaticProps = async () => {}` */
function isServerDataFunction(node: ts.Node): boolean {
  if (ts.isFunctionDeclaration(node)) return SERVER_DATA_FUNCTIONS.has(node.name?.text ?? '');
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name))
    return SERVER_DATA_FUNCTIONS.has(node.name.text);
  return false;
}

export const serviceRoleInClientRule = defineRule<Msg>({
  meta: {
    id: 'supabase/service-role-in-client',
    family: 'supabase',
    defaultSeverity: 'critical',
    cwe: [269, 284, 522],
    references: [
      'https://supabase.com/docs/guides/api/api-keys',
      'https://supabase.com/docs/guides/database/postgres/row-level-security#bypassing-row-level-security',
    ],
    docs: {
      title: {
        en: 'Supabase service_role key used in client-side code',
        ar: 'استخدام مفتاح service_role الخاص بـ Supabase في شيفرة المتصفح',
      },
      summary: {
        en: 'The service_role (or sb_secret_) key bypasses Row Level Security entirely. Code that runs in the browser either ships that key to every visitor, or (when the bundler strips a non-public env var) silently breaks and invites the "fix" of making it public. Client components must only ever use the anon/publishable key.',
        ar: 'مفتاح service_role (أو sb_secret_) يتجاوز Row Level Security كليًا. الشيفرة التي تعمل في المتصفح إما ترسل هذا المفتاح إلى كل زائر، أو تتعطل بصمت (عندما يحذف المجمّع متغير البيئة غير العام) فتدفع إلى "حلّ" المشكلة بجعله عامًا. مكوّنات المتصفح يجب ألا تستخدم إلا مفتاح anon/publishable.',
      },
      remediation: {
        text: {
          en: "Move privileged operations to server code (route handler, server action, edge function) that authenticates the user first. In client code, use the anon key and let RLS policies decide. Mark admin modules with import 'server-only' so the build fails if a client component imports them.",
          ar: "انقل العمليات ذات الصلاحيات إلى شيفرة الخادم (route handler أو server action أو edge function) بعد التحقق من هوية المستخدم أولًا. وفي شيفرة المتصفح استخدم مفتاح anon ودع سياسات RLS تقرّر. وعلّم وحدات الإدارة بـ import 'server-only' ليفشل البناء إن استوردها مكوّن متصفح.",
        },
        codeLanguage: 'ts',
        vulnerable: `'use client';
import { supabaseAdmin } from '@/lib/supabase/admin'; // service_role client
export function DeleteUser({ id }: { id: string }) {
  return <button onClick={() => supabaseAdmin.auth.admin.deleteUser(id)}>Delete</button>;
}`,
        fixed: `// lib/supabase/admin.ts
import 'server-only';
// ...

// app/admin/actions.ts
'use server';
export async function deleteUser(id: string) {
  const user = await requireAdmin(); // authenticate + authorise first
  await supabaseAdmin().auth.admin.deleteUser(id);
}`,
      },
    },
    messages: {
      envInClient: {
        en: '{name} (service-role key) is referenced in client-side code ({reason}).',
        ar: 'يُشار إلى المتغير {name} (مفتاح service-role) في شيفرة تعمل في المتصفح ({reason}).',
      },
      adminModuleImported: {
        en: 'Client-side code ({reason}) imports {module}, which uses the service-role key.',
        ar: 'شيفرة تعمل في المتصفح ({reason}) تستورد {module} الذي يستخدم مفتاح service-role.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    const memo = new Map<string, Promise<boolean>>();
    for (const file of ctx.files({ kinds: CODE_KINDS })) {
      const parsed = await ctx.parseTs(file);
      if (!parsed) continue;
      const sf = parsed.sourceFile;
      const verdict = await classifyRuntime(ctx, file, sf);
      if (verdict.runtime !== 'client') continue;

      for (const stmt of sf.statements) {
        if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
        if (stmt.importClause?.phaseModifier === ts.SyntaxKind.TypeKeyword) continue; // `import type` erases at build time
        const target = resolveImport(ctx, file.relPath, stmt.moduleSpecifier.text);
        if (!target || !(await isAdminModule(ctx, target, memo))) continue;
        const pos = nodePosition(sf, stmt);
        out.push({
          location: { file: file.relPath, line: pos.line, column: pos.column },
          messageId: 'adminModuleImported',
          params: { module: stmt.moduleSpecifier.text, reason: verdict.reason },
          evidence: scrubText(stmt.getText(sf), { maxLength: 160 }),
          confidence: verdict.confidence,
          fingerprintKey: `import:${stmt.moduleSpecifier.text}`,
        });
      }

      walk(sf, (node) => {
        // Pages Router data-fetching functions are stripped from the client bundle.
        if (isServerDataFunction(node)) return false;
        if (!ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node))
          return undefined;
        const name = ENV_REF.exec(dottedName(node) ?? '')?.[1];
        if (name === undefined) return undefined;
        // Public-prefixed names are reported by secrets/client-exposed-env.
        if (SERVICE_KEY_NAME.test(name) && publicPrefixOf(name) === undefined) {
          const pos = nodePosition(sf, node);
          out.push({
            location: { file: file.relPath, line: pos.line, column: pos.column },
            messageId: 'envInClient',
            params: { name, reason: verdict.reason },
            evidence: scrubText(node.getText(sf), { maxLength: 120 }),
            confidence: verdict.confidence,
            fingerprintKey: `env:${name}`,
          });
        }
        return false;
      });
    }
    return out;
  },
});
