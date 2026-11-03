import { parseSync, loadModule, type Node } from 'libpg-query';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseSql, skipTrivia } from '../../../../src/core/parsing/sql-parser.ts';
import { reachOf } from '../../../../src/rules/supabase/policy-expr.ts';
import { compareMigrationNames } from '../../../../src/rules/supabase/project.ts';
import {
  applyMigration,
  newModel,
  tablesMentioned,
  type SchemaModel,
} from '../../../../src/rules/supabase/schema-model.ts';

beforeAll(async () => {
  await loadModule();
});

async function replay(...files: string[]): Promise<SchemaModel> {
  const model = newModel();
  for (const [i, sql] of files.entries()) {
    const parsed = await parseSql(sql);
    applyMigration(model, {
      file: `m${i}.sql`,
      statements: parsed.statements,
      failures: parsed.failures,
    });
  }
  return model;
}

const table = (m: SchemaModel, k: string) => m.tables.get(k);

describe('parseSql', () => {
  it('returns statements with offsets of their first token', async () => {
    const sql =
      '-- header\ncreate table a (id int);\n/* c */ alter table a enable row level security;';
    const r = await parseSql(sql);
    expect(r.failures).toEqual([]);
    expect(r.statements.map((s) => sql.slice(s.start, s.start + 12))).toEqual([
      'create table',
      'alter table ',
    ]);
  });

  it('maps UTF-8 byte offsets to string offsets', async () => {
    const sql = "comment on table a is 'café ☕';\ncreate table b (id int);";
    const r = await parseSql(sql);
    expect(sql.slice(r.statements[1]?.start)).toMatch(/^create table b/);
  });

  it('isolates an unparseable statement and keeps the rest', async () => {
    const sql =
      'create table a (id int);\nalter table a enable row level securty;\ncreate table b (id int);';
    const r = await parseSql(sql);
    expect(r.statements).toHaveLength(2);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]?.text).toContain('securty');
    expect(r.failures[0]?.message).toMatch(/syntax error/);
  });

  it('never throws, even when the lexer fails (unterminated quote)', async () => {
    const r = await parseSql("create table a (id int);\nselect 'unterminated");
    expect(r.statements).toEqual([]);
    expect(r.failures).toHaveLength(1);
  });

  it('handles dollar-quoted bodies containing semicolons when falling back', async () => {
    const sql =
      'create function f() returns int language sql as $$ select 1; $$;\nbroken statement here;';
    const r = await parseSql(sql);
    expect(r.statements).toHaveLength(1);
    expect(r.failures).toHaveLength(1);
  });

  it('skips nested block comments', () => {
    expect(skipTrivia('/* a /* b */ c */  x', 0)).toBe(19);
  });
});

describe('migration replay', () => {
  it('orders migrations by their timestamp prefix', () => {
    const names = [
      'supabase/migrations/20240110_b.sql',
      'supabase/migrations/2_x.sql',
      'supabase/migrations/20240102_a.sql',
      'supabase/migrations/10_y.sql',
    ];
    expect([...names].sort(compareMigrationNames).map((n) => n.split('/').pop())).toEqual([
      '2_x.sql',
      '10_y.sql',
      '20240102_a.sql',
      '20240110_b.sql',
    ]);
  });

  it('lets the final state win: enable then disable, across files', async () => {
    const m = await replay(
      'create table t (id int); alter table t enable row level security;',
      'alter table public.t disable row level security;',
    );
    expect(table(m, 'public.t')).toMatchObject({ rls: false });
    expect(table(m, 'public.t')?.rlsLoc?.file).toBe('m1.sql');
  });

  it('keeps state on CREATE TABLE IF NOT EXISTS of an existing table', async () => {
    const m = await replay(
      'create table t (id int); alter table t enable row level security;',
      'create table if not exists t (id int);',
    );
    expect(table(m, 'public.t')?.rls).toBe(true);
  });

  it('handles schema-qualified, quoted and case-folded names', async () => {
    const m = await replay(
      'create table "Public"."MyTable" (id int); create table Public.Other (id int); create schema s; create table s.x (id int);',
    );
    expect([...m.tables.keys()].sort()).toEqual(['Public.MyTable', 'public.other', 's.x']);
  });

  it('follows renames and schema moves, carrying policies along', async () => {
    const m = await replay(
      'create table a (id int); alter table a enable row level security; create policy p on a using (true);',
      'alter table a rename to b; alter table b set schema private;',
    );
    expect(table(m, 'public.a')).toBeUndefined();
    expect(table(m, 'private.b')?.policies.has('p')).toBe(true);
  });

  it('applies DROP TABLE, and a re-created table starts fresh', async () => {
    const m = await replay(
      'create table t (id int); alter table t enable row level security;',
      'drop table if exists public.t, other; create table t (id int);',
    );
    expect(table(m, 'public.t')?.rls).toBe(false);
  });

  it('tracks CREATE / ALTER / RENAME / DROP POLICY', async () => {
    const m = await replay(
      'create table t (id int, o uuid); alter table t enable row level security;',
      'create policy p on t for update to authenticated using (o = auth.uid()); create policy q on t for select using (true);',
      'alter policy p on t using (true); alter policy q on public.t rename to r; drop policy if exists r on t;',
    );
    const t = table(m, 'public.t');
    expect([...(t?.policies.keys() ?? [])]).toEqual(['p']);
    const p = t?.policies.get('p');
    expect(p).toMatchObject({ command: 'update', roles: ['authenticated'], permissive: true });
    expect(reachOf(p?.qual)).toBe('true');
    expect(p?.loc.file).toBe('m2.sql');
  });

  it('records RESTRICTIVE policies and the default PUBLIC role', async () => {
    const m = await replay(
      'create table t (id int); create policy p on t as restrictive using (true); create policy q on t using (true);',
    );
    expect(table(m, 'public.t')?.policies.get('p')?.permissive).toBe(false);
    expect(table(m, 'public.t')?.policies.get('q')?.roles).toEqual(['public']);
  });

  it('tracks REVOKE ALL / GRANT for API roles, including ALL TABLES IN SCHEMA', async () => {
    const m = await replay(
      'create table a (id int); create table b (id int); revoke all on a from anon, authenticated;',
      'revoke all on all tables in schema public from anon; grant select on b to anon; revoke insert on b from authenticated;',
    );
    expect([...(table(m, 'public.a')?.revoked ?? [])].sort()).toEqual(['anon', 'authenticated']);
    expect([...(table(m, 'public.b')?.revoked ?? [])]).toEqual([]);
  });

  it('tracks views (security_invoker) and functions (security definer, revoke execute)', async () => {
    const m = await replay(
      'create view v1 as select 1; create view v2 with (security_invoker = on) as select 1; create view v3 as select 1; alter view v3 set (security_invoker = true);',
      'create function f() returns int language sql security definer as $$ select 1 $$; create function g() returns trigger language plpgsql security definer as $$ begin return new; end $$; revoke execute on function f() from public, anon;',
    );
    expect([...m.views.values()].map((v) => [v.name, v.securityInvoker])).toEqual([
      ['v1', false],
      ['v2', true],
      ['v3', true],
    ]);
    expect(m.functions.get('public.f')).toMatchObject({
      securityDefiner: true,
      returnsTrigger: false,
    });
    expect([...(m.functions.get('public.f')?.revoked ?? [])].sort()).toEqual(['anon', 'public']);
    expect(m.functions.get('public.g')?.returnsTrigger).toBe(true);
  });

  it('marks tables touched by unparseable statements as uncertain, even before creation', async () => {
    const m = await replay(
      'alter table later enable row level securty;',
      'create table later (id int); create table fine (id int);',
    );
    expect(table(m, 'public.later')?.uncertain).toBe(true);
    expect(table(m, 'public.fine')?.uncertain).toBe(false);
    expect(m.uncertainties[0]).toMatchObject({ reason: 'parse-failed', tables: ['public.later'] });
  });

  it('marks everything uncertain when a failed statement names no table', async () => {
    const m = await replay('create table t (id int); garbage garbage garbage;');
    expect(m.globallyUncertain).toBe(true);
  });

  it('marks tables touched by DO blocks as uncertain (PL/pgSQL is not executed)', async () => {
    const m = await replay(
      "create table t (id int); do $$ begin execute 'alter table public.t enable row level security'; end $$;",
    );
    expect(table(m, 'public.t')).toMatchObject({ rls: false, uncertain: true });
  });

  it('extracts table names from raw SQL', () => {
    expect(
      tablesMentioned(
        'ALTER TABLE ONLY "Public"."X" enable; insert into y values (1); create policy p on s.z',
      ),
    ).toEqual(['Public.X', 'public.y', 's.z']);
  });
});

describe('policy expressions', () => {
  const q = (expr: string): Node | undefined => {
    const r = parseSync(`create policy p on t using (${expr})`);
    const stmt = r.stmts?.[0]?.stmt;
    return stmt && 'CreatePolicyStmt' in stmt ? stmt.CreatePolicyStmt.qual : undefined;
  };

  it.each([
    ['true', 'true'],
    ['TRUE', 'true'],
    ["'true'::boolean", 'true'],
    ['1 = 1', 'true'],
    ['true or owner = auth.uid()', 'true'],
    ['auth.uid() is not null', 'authenticated'],
    ['(select auth.uid()) is not null', 'authenticated'],
    ["auth.role() = 'authenticated'", 'authenticated'],
    ["(auth.jwt() ->> 'role') = 'authenticated'", 'authenticated'],
    ['auth.uid() is not null and true', 'authenticated'],
    ['auth.uid() = owner', 'scoped'],
    ['(select auth.uid()) = user_id', 'scoped'],
    ['auth.uid() is not null and owner = auth.uid()', 'scoped'],
    ["(auth.jwt() ->> 'role') = 'admin'", 'scoped'],
    ['exists (select 1 from members m where m.user_id = auth.uid())', 'scoped'],
    ['false', 'scoped'],
    ['1 = 2', 'scoped'],
  ])('%s → %s', (expr, reach) => {
    expect(reachOf(q(expr))).toBe(reach);
  });
});
