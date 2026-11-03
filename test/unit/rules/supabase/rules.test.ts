import { describe, expect, it } from 'vitest';
import { classifyRuntime } from '../../../../src/analysis/runtime.ts';
import { resolveSettings } from '../../../../src/core/config/settings.ts';
import { ProjectContext } from '../../../../src/core/engine/context.ts';
import { scan } from '../../../../src/core/engine/engine.ts';
import type { Rule } from '../../../../src/core/engine/rule.ts';
import { discoverFiles } from '../../../../src/core/discovery/walker.ts';
import { markdownReporter } from '../../../../src/reporters/markdown.ts';
import { terminalReporter } from '../../../../src/reporters/terminal.ts';
import { ALL_RULES } from '../../../../src/rules/index.ts';
import { verdict } from '../../../../src/rules/supabase/permissive-policy.rule.ts';
import { rlsDisabledRule } from '../../../../src/rules/supabase/rls-disabled.rule.ts';
import { rlsNoPoliciesRule } from '../../../../src/rules/supabase/rls-no-policies.rule.ts';
import { permissivePolicyRule } from '../../../../src/rules/supabase/permissive-policy.rule.ts';
import {
  securityDefinerFunctionRule,
  securityDefinerViewRule,
} from '../../../../src/rules/supabase/security-definer.rule.ts';
import { serviceRoleInClientRule } from '../../../../src/rules/supabase/service-role-in-client.rule.ts';
import { makeProject } from '../../../helpers/project.ts';

const M = 'supabase/migrations';

async function run(
  rule: Rule,
  files: Record<string, string>,
  config?: Parameters<typeof resolveSettings>[0],
) {
  const root = await makeProject(files);
  const r = await scan({ root, settings: resolveSettings(config), rules: [rule] });
  expect(r.complete).toBe(true);
  return r;
}

const ids = (r: Awaited<ReturnType<typeof run>>) =>
  r.findings.map(
    (f) =>
      `${f.messageId} ${String(f.params['table'] ?? f.params['view'] ?? f.params['function'] ?? f.params['name'] ?? f.params['module'])} ${f.location.file}:${f.location.line}`,
  );

describe('supabase/rls-disabled', () => {
  it('reports exposed tables without RLS, pointing at CREATE or at the DISABLE', async () => {
    const r = await run(rlsDisabledRule, {
      [`${M}/1_init.sql`]:
        'create table a (id int);\ncreate table b (id int);\nalter table b enable row level security;\ncreate policy p on b using (auth.uid() is not null);',
      [`${M}/2_oops.sql`]: '\nalter table b disable row level security;',
    });
    expect(ids(r)).toEqual([
      `disabled public.a ${M}/1_init.sql:1`,
      `disabledWithPolicies public.b ${M}/2_oops.sql:2`,
    ]);
    expect(r.findings[0]).toMatchObject({ severity: 'critical', confidence: 'high' });
  });

  it.each([
    ['RLS enabled later', 'create table a (id int);', 'alter table a enable row level security;'],
    ['non-exposed schema', 'create schema private; create table private.a (id int);', ''],
    [
      'privileges revoked from the API roles',
      'create table a (id int);',
      'revoke all on table a from anon, authenticated;',
    ],
    ['dropped', 'create table a (id int);', 'drop table a;'],
  ])('does not report: %s', async (_label, first, second) => {
    expect(
      (await run(rlsDisabledRule, { [`${M}/1.sql`]: first, [`${M}/2.sql`]: second })).findings,
    ).toEqual([]);
  });

  it('reads exposed schemas from supabase/config.toml, and settings override both', async () => {
    const files = {
      'supabase/config.toml': '[api]\nschemas = ["api"]\n',
      [`${M}/1.sql`]:
        'create schema api; create table api.items (id int); create table public.x (id int);',
    };
    expect(ids(await run(rlsDisabledRule, files)).map((s) => s.split(' ')[1])).toEqual([
      'api.items',
    ]);
    const overridden = await run(rlsDisabledRule, files, {
      version: 1,
      supabase: { exposedSchemas: ['public'] },
    });
    expect(ids(overridden).map((s) => s.split(' ')[1])).toEqual(['public.x']);
  });

  it('finds migrations in monorepo subprojects and honours configured directories', async () => {
    const files = {
      [`apps/web/${M}/1.sql`]: 'create table a (id int);',
      'db/migrations/1.sql': 'create table b (id int);',
    };
    expect(ids(await run(rlsDisabledRule, files))).toEqual([
      `disabled public.a apps/web/${M}/1.sql:1`,
    ]);
    const configured = await run(rlsDisabledRule, files, {
      version: 1,
      supabase: { migrationsDirs: ['db/migrations'] },
    });
    expect(ids(configured)).toEqual(['disabled public.b db/migrations/1.sql:1']);
  });

  it('reports an unverifiable table with low confidence and a parse-failed notice, never silently', async () => {
    const r = await run(rlsDisabledRule, {
      [`${M}/1.sql`]: 'create table a (id int);\nalter table a enable row level securty;',
    });
    expect(r.findings[0]).toMatchObject({ messageId: 'unverified', confidence: 'low' });
    expect(r.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'parse-failed', level: 'warning', line: 2 }),
    );
  });

  it('states the dashboard blind spot when Supabase is used but there are no migrations', async () => {
    const r = await run(rlsDisabledRule, {
      'package.json': '{"dependencies":{"@supabase/supabase-js":"^2"}}',
      'src/a.ts': '',
    });
    expect(r.findings).toEqual([]);
    expect(r.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'no-migrations', level: 'warning' }),
    );
    const out = terminalReporter.render(r, {
      locale: 'en',
      color: false,
      toolVersion: 't',
      failOn: 'high',
      minConfidence: 'low',
    });
    expect(out).toContain('Supabase dashboard');
    expect(out).toContain('Coverage is PARTIAL');
    expect(out).not.toContain('\nNo findings.\n');
    const md = markdownReporter.render(r, {
      locale: 'ar',
      color: false,
      toolVersion: 't',
      failOn: 'high',
      minConfidence: 'low',
    });
    expect(md).toContain('تغطية جزئية');
  });

  it('emits a dynamic-sql notice (partial coverage) for DO blocks that change RLS', async () => {
    const r = await run(rlsDisabledRule, {
      [`${M}/1.sql`]:
        "create table t (id int);\nalter table t enable row level security;\ndo $$ begin execute 'alter table public.t disable row level security'; end $$;",
    });
    expect(r.findings).toEqual([]);
    expect(r.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'dynamic-sql', line: 3, params: { tables: 'public.t' } }),
    );
  });

  it('stays silent about migrations for projects that do not use Supabase', async () => {
    const r = await run(rlsDisabledRule, { 'package.json': '{"dependencies":{"express":"^4"}}' });
    expect(r.diagnostics).toEqual([]);
  });
});

describe('supabase/rls-no-policies', () => {
  it('reports RLS with no permissive policy, at the ENABLE statement', async () => {
    const r = await run(rlsNoPoliciesRule, {
      [`${M}/1.sql`]:
        'create table a (id int);\nalter table a enable row level security;\ncreate policy r on a as restrictive using (true);',
    });
    expect(ids(r)).toEqual([`noPolicies public.a ${M}/1.sql:2`]);
    expect(r.findings[0]?.severity).toBe('low');
  });

  it.each([
    ['a permissive policy exists', 'create policy p on a using (auth.uid() = id);'],
    ['the table is explicitly server-only', 'revoke all on a from anon, authenticated;'],
  ])('does not report when %s', async (_l, extra) => {
    const sql = `create table a (id uuid); alter table a enable row level security; ${extra}`;
    expect((await run(rlsNoPoliciesRule, { [`${M}/1.sql`]: sql })).findings).toEqual([]);
  });
});

describe('supabase/permissive-policy', () => {
  const base = (name: string) =>
    `create table ${name} (id int, owner uuid); alter table ${name} enable row level security;\n`;

  it('reports wide-open policies with severity by command, audience and table', async () => {
    const r = await run(permissivePolicyRule, {
      [`${M}/1.sql`]: [
        base('orders'),
        'create policy w on orders for delete to anon using (true);',
        base('notes'),
        'create policy u on notes for update to authenticated using (auth.uid() is not null);',
        base('profiles'),
        'create policy r on profiles for select using (true);',
        base('waitlist'),
        'create policy i on waitlist for insert to anon with check (true);',
        base('countries'),
        'create policy c on countries for select using (true);',
      ].join('\n'),
    });
    expect(
      r.findings.map((f) => [f.params['table'], f.messageId, f.severity, f.confidence]),
    ).toEqual([
      ['public.orders', 'writeAnyone', 'critical', 'high'],
      ['public.notes', 'writeAnyAuthenticated', 'high', 'high'],
      ['public.profiles', 'readAnyone', 'high', 'medium'],
      ['public.waitlist', 'insertAnyone', 'medium', 'medium'],
      ['public.countries', 'readAnyone', 'low', 'low'],
    ]);
  });

  it.each([
    ['owner-scoped', 'create policy p on t for update using (auth.uid() = owner);'],
    ['restrictive', 'create policy p on t as restrictive for update using (true);'],
    ['service_role only', 'create policy p on t for all to service_role using (true);'],
    [
      'admin claim check',
      "create policy p on t for delete using ((auth.jwt() ->> 'role') = 'admin');",
    ],
    [
      'replaced by a scoped policy',
      'create policy p on t for all using (true); drop policy p on t; create policy p on t for all using (owner = auth.uid());',
    ],
    [
      'lookup table readable by logged-in users',
      'create policy p on countries for select to authenticated using (true);',
    ],
  ])('does not report: %s', async (_l, sql) => {
    const r = await run(permissivePolicyRule, {
      [`${M}/1.sql`]: `${base('t')}${base('countries')}${sql}`,
    });
    expect(r.findings).toEqual([]);
  });

  it('leaves tables with RLS disabled to supabase/rls-disabled', async () => {
    const r = await run(permissivePolicyRule, {
      [`${M}/1.sql`]: 'create table t (id int); create policy p on t for all using (true);',
    });
    expect(r.findings).toEqual([]);
  });

  it('has a complete severity matrix', () => {
    expect(verdict('insert', 'anyAuthenticated', 'posts')).toMatchObject({ severity: 'medium' });
    expect(verdict('select', 'anyAuthenticated', 'countries')).toBeUndefined();
    expect(verdict('all', 'anyone', 'countries')).toMatchObject({ severity: 'critical' });
    expect(verdict('select', 'anyone', 'widgets')).toMatchObject({
      severity: 'medium',
      confidence: 'medium',
    });
  });
});

describe('supabase/security-definer-view and -function', () => {
  it('reports views without security_invoker and callable SECURITY DEFINER functions in exposed schemas', async () => {
    const sql = [
      'create view v as select 1;',
      'create view ok with (security_invoker = true) as select 1;',
      'create schema private; create view private.hidden as select 1;',
      'create function f() returns int language sql security definer as $$ select 1 $$;',
      'create function g() returns int language sql security definer as $$ select 1 $$; revoke execute on function g() from public, anon;',
      'create function h() returns int language sql security definer as $$ select 1 $$; revoke execute on function h() from public, anon, authenticated;',
      'create function i() returns int language sql as $$ select 1 $$;',
      'create function t() returns trigger language plpgsql security definer as $$ begin return new; end $$;',
    ].join('\n');
    const views = await run(securityDefinerViewRule, { [`${M}/1.sql`]: sql });
    expect(ids(views)).toEqual([`view public.v ${M}/1.sql:1`]);
    const fns = await run(securityDefinerFunctionRule, { [`${M}/1.sql`]: sql });
    expect(
      fns.findings.map((f) => [f.params['function'], f.messageId, f.severity, f.confidence]),
    ).toEqual([
      ['public.f', 'function', 'medium', 'low'],
      ['public.g', 'functionAuthenticated', 'low', 'low'],
    ]);
  });
});

describe('supabase/service-role-in-client', () => {
  const next = { 'package.json': '{"dependencies":{"next":"15.0.0"}}' };
  const admin = { 'src/lib/admin.ts': 'export const k = process.env.SUPABASE_SERVICE_ROLE_KEY;' };

  it('reports service-role env references and admin-module imports in client code', async () => {
    const r = await run(serviceRoleInClientRule, {
      ...next,
      ...admin,
      'src/components/A.tsx':
        "'use client';\nimport { k } from '@/lib/admin';\nexport const x = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      'src/pages/index.tsx':
        "import { k } from '../lib/admin';\nexport default function P() { return null; }",
    });
    expect(ids(r)).toEqual([
      'adminModuleImported @/lib/admin src/components/A.tsx:2',
      'envInClient SUPABASE_SERVICE_ROLE_KEY src/components/A.tsx:3',
      'adminModuleImported ../lib/admin src/pages/index.tsx:1',
    ]);
    expect(r.findings.map((f) => f.confidence)).toEqual(['high', 'high', 'medium']);
  });

  it('detects an embedded service_role JWT or sb_secret_ key in an imported module', async () => {
    const jwt = [
      'eyJhbGciOiJIUzI1NiJ9',
      Buffer.from('{"iss":"supabase","role":"service_role"}').toString('base64url'),
      'Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4',
    ].join('.');
    const r = await run(serviceRoleInClientRule, {
      'package.json': '{"devDependencies":{"vite":"5"}}',
      'src/lib/sb.ts': `export const KEY = '${jwt}';`,
      'src/App.tsx': "import { KEY } from './lib/sb';\nexport const App = () => KEY;",
    });
    expect(ids(r)).toEqual(['adminModuleImported ./lib/sb src/App.tsx:1']);
  });

  it.each([
    [
      'App Router server component',
      {
        'src/app/admin/page.tsx':
          "import { k } from '@/lib/admin';\nexport default function P() { return null; }",
      },
    ],
    [
      'route handler',
      { 'src/app/api/x/route.ts': 'export const k = process.env.SUPABASE_SERVICE_ROLE_KEY;' },
    ],
    [
      "'use server' action",
      {
        'src/actions.ts': "'use server';\nexport const k = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      },
    ],
    [
      'server-only module',
      {
        'src/lib/x.ts':
          "import 'server-only';\nexport const k = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      },
    ],
    [
      'getServerSideProps',
      {
        'src/pages/r.tsx':
          'export async function getServerSideProps() { return { props: { k: process.env.SUPABASE_SERVICE_ROLE_KEY } }; }\nexport default function R() { return null; }',
      },
    ],
    [
      'unknown runtime (no signal)',
      { 'src/lib/y.ts': 'export const k = process.env.SUPABASE_SERVICE_ROLE_KEY;' },
    ],
    [
      'public-prefixed name (owned by secrets/client-exposed-env)',
      {
        'src/c.tsx':
          "'use client';\nexport const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;",
      },
    ],
    [
      'anon client import',
      {
        'src/lib/client.ts': 'export const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;',
        'src/c.tsx': "'use client';\nimport { k } from './lib/client';",
      },
    ],
    [
      'type-only import of an admin module',
      { 'src/c.tsx': "'use client';\nimport type { k } from '@/lib/admin';" },
    ],
  ])('does not report: %s', async (_l, files) => {
    expect((await run(serviceRoleInClientRule, { ...next, ...admin, ...files })).findings).toEqual(
      [],
    );
  });
});

describe('classifyRuntime', () => {
  async function verdictFor(files: Record<string, string>, file: string) {
    const root = await makeProject(files);
    const { files: recs } = await discoverFiles({ root });
    const ctx = new ProjectContext(root, resolveSettings(undefined), recs);
    const rec = ctx.file(file);
    if (!rec) throw new Error(file);
    const parsed = await ctx.parseTs(rec);
    if (!parsed) throw new Error('parse');
    return (await classifyRuntime(ctx, rec, parsed.sourceFile)).runtime;
  }

  it.each([
    [
      { 'package.json': '{"dependencies":{"next":"15"}}', 'app/page.tsx': 'export default 1;' },
      'app/page.tsx',
      'server',
    ],
    [
      {
        'package.json': '{"dependencies":{"next":"15"}}',
        'app/c.tsx': "'use client'; export default 1;",
      },
      'app/c.tsx',
      'client',
    ],
    [
      { 'package.json': '{"dependencies":{"next":"15"}}', 'pages/index.tsx': 'export default 1;' },
      'pages/index.tsx',
      'client',
    ],
    [
      { 'package.json': '{"dependencies":{"next":"15"}}', 'pages/api/x.ts': 'export default 1;' },
      'pages/api/x.ts',
      'server',
    ],
    [
      { 'package.json': '{"dependencies":{"next":"15"}}', 'components/x.tsx': 'export default 1;' },
      'components/x.tsx',
      'unknown',
    ],
    [
      { 'package.json': '{"devDependencies":{"vite":"5"}}', 'src/main.tsx': 'export default 1;' },
      'src/main.tsx',
      'client',
    ],
    [
      {
        'package.json': '{"devDependencies":{"vite":"5"}}',
        'server/index.ts': 'export default 1;',
      },
      'server/index.ts',
      'server',
    ],
    [
      {
        'apps/web/package.json': '{"dependencies":{"react-scripts":"5"}}',
        'apps/web/src/a.ts': 'export default 1;',
      },
      'apps/web/src/a.ts',
      'client',
    ],
    [
      { 'supabase/functions/x/index.ts': 'export default 1;' },
      'supabase/functions/x/index.ts',
      'server',
    ],
    [{ 'lib/x.ts': 'export const u = import.meta.env.VITE_URL;' }, 'lib/x.ts', 'client'],
    [
      { 'middleware.ts': 'export default 1;', 'package.json': '{"dependencies":{"next":"15"}}' },
      'middleware.ts',
      'server',
    ],
  ])('%#: %s → %s', async (files, file, expected) => {
    expect(await verdictFor(files, file)).toBe(expected);
  });
});

describe('registry', () => {
  it('contains every supabase rule exactly once', () => {
    expect(
      ALL_RULES.filter((r) => r.meta.family === 'supabase')
        .map((r) => r.meta.id)
        .sort(),
    ).toEqual([
      'supabase/permissive-policy',
      'supabase/rls-disabled',
      'supabase/rls-no-policies',
      'supabase/security-definer-function',
      'supabase/security-definer-view',
      'supabase/service-role-in-client',
    ]);
  });
});
