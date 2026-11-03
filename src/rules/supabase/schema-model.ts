import type { Node, RangeVar } from 'libpg-query';
import type { SqlParseFailure, SqlStatement } from '../../core/parsing/sql-parser.ts';

/**
 * Replays SQL migrations in order and keeps the *final* state of every table, policy,
 * view and function: later statements override earlier ones (enable then disable, create
 * then drop, rename, alter policy, …). See docs/adr/0002-sql-parser.md.
 *
 * Unqualified names resolve to `public` (Supabase's default search_path for migrations).
 */

export interface Loc {
  readonly file: string;
  readonly start: number; // character offset in file
  readonly text: string; // statement text
}

export type Command = 'all' | 'select' | 'insert' | 'update' | 'delete';

export interface PolicyState {
  name: string;
  command: Command;
  permissive: boolean;
  /** Lower-cased role names; 'public' when no TO clause. */
  roles: string[];
  qual: Node | undefined;
  withCheck: Node | undefined;
  loc: Loc;
}

export interface TableState {
  schema: string;
  name: string;
  rls: boolean;
  force: boolean;
  created: Loc;
  /** Last statement that changed RLS on/off. */
  rlsLoc: Loc | undefined;
  policies: Map<string, PolicyState>;
  /** All privileges revoked from these roles (anon, authenticated, public). */
  revoked: Set<string>;
  /** Touched by a statement we could not parse or execute (DO block): state is unknown. */
  uncertain: boolean;
}

export interface ViewState {
  schema: string;
  name: string;
  securityInvoker: boolean;
  loc: Loc;
}

export interface FunctionState {
  schema: string;
  name: string;
  securityDefiner: boolean;
  returnsTrigger: boolean;
  revoked: Set<string>;
  loc: Loc;
}

export interface Uncertainty {
  readonly loc: Loc;
  readonly reason: 'parse-failed' | 'dynamic-sql';
  /** Tables named in the statement text; empty when none could be identified. */
  readonly tables: readonly string[];
}

export interface SchemaModel {
  readonly tables: Map<string, TableState>;
  readonly views: Map<string, ViewState>;
  readonly functions: Map<string, FunctionState>;
  readonly uncertainties: Uncertainty[];
  /** An unparseable statement whose target could not be identified: every table is suspect. */
  globallyUncertain: boolean;
  /** Tables named by an unparseable statement before they were created. */
  readonly pendingUncertain: Set<string>;
}

export interface MigrationInput {
  readonly file: string;
  readonly statements: readonly SqlStatement[];
  readonly failures: readonly SqlParseFailure[];
}

export const key = (schema: string, name: string): string => `${schema}.${name}`;

function rel(r: RangeVar | undefined): { schema: string; name: string } | undefined {
  if (!r?.relname) return undefined;
  return { schema: r.schemaname ?? 'public', name: r.relname };
}

function strings(list: readonly Node[] | undefined): string[] {
  return (list ?? []).map((n) => ('String' in n ? (n.String.sval ?? '') : ''));
}

/** `a.b.c` from a List / String node: last item is the object name. */
function qualified(n: Node): string[] {
  if ('List' in n) return strings(n.List.items);
  if ('String' in n) return [n.String.sval ?? ''];
  return [];
}

function roleNames(list: readonly Node[] | undefined): string[] {
  const out = (list ?? []).map((n) => {
    if (!('RoleSpec' in n)) return '';
    const r = n.RoleSpec;
    return r.roletype === 'ROLESPEC_PUBLIC' ? 'public' : (r.rolename ?? '').toLowerCase();
  });
  return out.length === 0 ? ['public'] : out;
}

function defBool(n: Node): boolean | undefined {
  if ('Boolean' in n) return n.Boolean.boolval === true;
  if ('String' in n)
    return ['true', 'on', 't', 'yes', '1'].includes((n.String.sval ?? '').toLowerCase());
  if ('Integer' in n) return n.Integer.ival === 1;
  return undefined;
}

function optionTrue(options: readonly Node[] | undefined, name: string): boolean | undefined {
  for (const o of options ?? []) {
    if ('DefElem' in o && o.DefElem.defname === name) {
      return o.DefElem.arg ? defBool(o.DefElem.arg) : true;
    }
  }
  return undefined;
}

/** Table-like identifiers in raw SQL, for statements we could not parse. */
const TARGET =
  /\b(?:table|on|into|update|from|view)\s+(?:only\s+)?(?:if\s+(?:not\s+)?exists\s+)?((?:"[^"]{1,63}"|[A-Za-z_][\w$]{0,62})(?:\s*\.\s*(?:"[^"]{1,63}"|[A-Za-z_][\w$]{0,62}))?)/gi;

export function tablesMentioned(sql: string): string[] {
  const out = new Set<string>();
  TARGET.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TARGET.exec(sql)) !== null) {
    // Postgres folds unquoted identifiers to lower case; quoted ones keep their case.
    const parts = (m[1] ?? '')
      .split('.')
      .map((p) => p.trim())
      .map((p) => (p.startsWith('"') ? p.slice(1, -1) : p.toLowerCase()));
    const [schema, name] =
      parts.length === 2 ? [parts[0] ?? 'public', parts[1] ?? ''] : ['public', parts[0] ?? ''];
    if (name && !/^(?:select|set|all|each|row|statement|conflict|true|false|null)$/i.test(name)) {
      out.add(key(schema, name));
    }
  }
  return [...out];
}

export function newModel(): SchemaModel {
  return {
    tables: new Map(),
    views: new Map(),
    functions: new Map(),
    uncertainties: [],
    globallyUncertain: false,
    pendingUncertain: new Set(),
  };
}

/** Apply one migration file (statements and failures interleaved in source order). */
export function applyMigration(model: SchemaModel, input: MigrationInput): void {
  type Event = { start: number; stmt?: SqlStatement; failure?: SqlParseFailure };
  const events: Event[] = [
    ...input.statements.map((s) => ({ start: s.start, stmt: s })),
    ...input.failures.map((f) => ({ start: f.start, failure: f })),
  ].sort((a, b) => a.start - b.start);

  for (const e of events) {
    if (e.failure) {
      markUncertain(
        model,
        { file: input.file, start: e.failure.start, text: e.failure.text },
        'parse-failed',
      );
    } else if (e.stmt) {
      applyStatement(model, e.stmt.node, {
        file: input.file,
        start: e.stmt.start,
        text: e.stmt.text,
      });
    }
  }
}

function markUncertain(model: SchemaModel, loc: Loc, reason: Uncertainty['reason']): void {
  const tables = tablesMentioned(loc.text);
  model.uncertainties.push({ loc, reason, tables });
  if (tables.length === 0) {
    model.globallyUncertain = true;
    return;
  }
  for (const k of tables) {
    const t = model.tables.get(k);
    if (t) t.uncertain = true;
    else model.pendingUncertain.add(k);
  }
}

function applyStatement(model: SchemaModel, node: Node, loc: Loc): void {
  if ('CreateStmt' in node) {
    const r = rel(node.CreateStmt.relation);
    if (!r) return;
    const k = key(r.schema, r.name);
    if (model.tables.has(k)) return; // IF NOT EXISTS no-op (or an error in Postgres: keep state)
    model.tables.set(k, newTable(r, loc, model.pendingUncertain.delete(k)));
    return;
  }
  if ('CreateTableAsStmt' in node) {
    const r = rel(node.CreateTableAsStmt.into?.rel);
    if (!r || node.CreateTableAsStmt.objtype === 'OBJECT_MATVIEW') return;
    const k = key(r.schema, r.name);
    if (!model.tables.has(k))
      model.tables.set(k, newTable(r, loc, model.pendingUncertain.delete(k)));
    return;
  }
  if ('AlterTableStmt' in node) {
    const s = node.AlterTableStmt;
    const r = rel(s.relation);
    if (!r) return;
    if (s.objtype === 'OBJECT_VIEW') {
      const v = model.views.get(key(r.schema, r.name));
      for (const c of s.cmds ?? []) {
        if (
          v &&
          'AlterTableCmd' in c &&
          c.AlterTableCmd.subtype === 'AT_SetRelOptions' &&
          c.AlterTableCmd.def &&
          'List' in c.AlterTableCmd.def
        ) {
          const on = optionTrue(c.AlterTableCmd.def.List.items, 'security_invoker');
          if (on !== undefined) v.securityInvoker = on;
        }
      }
      return;
    }
    const t = model.tables.get(key(r.schema, r.name));
    if (!t) return;
    for (const c of s.cmds ?? []) {
      if (!('AlterTableCmd' in c)) continue;
      switch (c.AlterTableCmd.subtype) {
        case 'AT_EnableRowSecurity':
          t.rls = true;
          t.rlsLoc = loc;
          break;
        case 'AT_DisableRowSecurity':
          t.rls = false;
          t.rlsLoc = loc;
          break;
        case 'AT_ForceRowSecurity':
          t.force = true;
          break;
        case 'AT_NoForceRowSecurity':
          t.force = false;
          break;
        default:
          break;
      }
    }
    return;
  }
  if ('DropStmt' in node) {
    const s = node.DropStmt;
    for (const obj of s.objects ?? []) {
      const parts = 'ObjectWithArgs' in obj ? strings(obj.ObjectWithArgs.objname) : qualified(obj);
      if (s.removeType === 'OBJECT_TABLE') model.tables.delete(objKey(parts));
      else if (s.removeType === 'OBJECT_VIEW') model.views.delete(objKey(parts));
      else if (s.removeType === 'OBJECT_FUNCTION') model.functions.delete(objKey(parts));
      else if (s.removeType === 'OBJECT_POLICY') {
        const policy = parts.pop();
        const t = model.tables.get(objKey(parts));
        if (t && policy !== undefined) t.policies.delete(policy);
      } else if (s.removeType === 'OBJECT_SCHEMA') {
        for (const schema of parts) {
          for (const [k, t] of model.tables) if (t.schema === schema) model.tables.delete(k);
        }
      }
    }
    return;
  }
  if ('RenameStmt' in node) {
    const s = node.RenameStmt;
    const r = rel(s.relation);
    if (!r || !s.newname) return;
    if (s.renameType === 'OBJECT_TABLE') {
      const t = model.tables.get(key(r.schema, r.name));
      if (!t) return;
      model.tables.delete(key(r.schema, r.name));
      t.name = s.newname;
      model.tables.set(key(t.schema, t.name), t);
    } else if (s.renameType === 'OBJECT_POLICY' && s.subname) {
      const t = model.tables.get(key(r.schema, r.name));
      const p = t?.policies.get(s.subname);
      if (t && p) {
        t.policies.delete(s.subname);
        p.name = s.newname;
        t.policies.set(p.name, p);
      }
    }
    return;
  }
  if ('AlterObjectSchemaStmt' in node) {
    const s = node.AlterObjectSchemaStmt;
    const r = rel(s.relation);
    if (s.objectType !== 'OBJECT_TABLE' || !r || !s.newschema) return;
    const t = model.tables.get(key(r.schema, r.name));
    if (!t) return;
    model.tables.delete(key(r.schema, r.name));
    t.schema = s.newschema;
    model.tables.set(key(t.schema, t.name), t);
    return;
  }
  if ('CreatePolicyStmt' in node) {
    const s = node.CreatePolicyStmt;
    const r = rel(s.table);
    const t = r ? model.tables.get(key(r.schema, r.name)) : undefined;
    if (!t || !s.policy_name) return;
    t.policies.set(s.policy_name, {
      name: s.policy_name,
      command: (s.cmd_name ?? 'all') as Command,
      // libpg-query omits false booleans (protobuf defaults): absent means RESTRICTIVE.
      permissive: s.permissive === true,
      roles: roleNames(s.roles),
      qual: s.qual,
      withCheck: s.with_check,
      loc,
    });
    return;
  }
  if ('AlterPolicyStmt' in node) {
    const s = node.AlterPolicyStmt;
    const r = rel(s.table);
    const p =
      r && s.policy_name
        ? model.tables.get(key(r.schema, r.name))?.policies.get(s.policy_name)
        : undefined;
    if (!p) return;
    if (s.roles) p.roles = roleNames(s.roles);
    if (s.qual) p.qual = s.qual;
    if (s.with_check) p.withCheck = s.with_check;
    p.loc = loc;
    return;
  }
  if ('ViewStmt' in node) {
    const r = rel(node.ViewStmt.view);
    if (!r) return;
    model.views.set(key(r.schema, r.name), {
      ...r,
      securityInvoker: optionTrue(node.ViewStmt.options, 'security_invoker') === true,
      loc,
    });
    return;
  }
  if ('CreateFunctionStmt' in node) {
    const s = node.CreateFunctionStmt;
    const parts = strings(s.funcname);
    const name = parts.pop() ?? '';
    const schema = parts.pop() ?? 'public';
    const returnType = strings(s.returnType?.names).pop();
    const k = key(schema, name);
    const prev = model.functions.get(k);
    model.functions.set(k, {
      schema,
      name,
      securityDefiner: optionTrue(s.options, 'security') === true,
      returnsTrigger: returnType === 'trigger' || returnType === 'event_trigger',
      revoked: prev?.revoked ?? new Set(),
      loc,
    });
    if (bodyLooksLikeDdl(s.options)) markUncertain(model, loc, 'dynamic-sql');
    return;
  }
  if ('AlterFunctionStmt' in node) {
    const f = model.functions.get(objKey(strings(node.AlterFunctionStmt.func?.objname)));
    const sec = optionTrue(node.AlterFunctionStmt.actions, 'security');
    if (f && sec !== undefined) f.securityDefiner = sec;
    return;
  }
  if ('GrantStmt' in node) {
    applyGrant(model, node.GrantStmt);
    return;
  }
  if ('DoStmt' in node) {
    // PL/pgSQL blocks are not executed. If one touches RLS or policies, the affected tables'
    // final state is unknown.
    const body =
      node.DoStmt.args
        ?.map((a) =>
          'DefElem' in a && a.DefElem.arg && 'String' in a.DefElem.arg
            ? (a.DefElem.arg.String.sval ?? '')
            : '',
        )
        .join('\n') ?? '';
    if (
      /row\s+level\s+security|\bpolicy\b|\bdrop\s+table\b|\bcreate\s+table\b|\bexecute\b/i.test(
        body,
      )
    ) {
      markUncertain(model, { ...loc, text: body }, 'dynamic-sql');
    }
  }
}

function bodyLooksLikeDdl(options: readonly Node[] | undefined): boolean {
  for (const o of options ?? []) {
    if ('DefElem' in o && o.DefElem.defname === 'as' && o.DefElem.arg && 'List' in o.DefElem.arg) {
      const body = strings(o.DefElem.arg.List.items).join('\n');
      if (/row\s+level\s+security|\b(?:create|drop|alter)\s+policy\b/i.test(body)) return true;
    }
  }
  return false;
}

const ROLES_OF_INTEREST = new Set(['anon', 'authenticated', 'public']);

function applyGrant(
  model: SchemaModel,
  g: NonNullable<Extract<Node, { GrantStmt: unknown }>['GrantStmt']>,
): void {
  const privs = (g.privileges ?? []).map((n) =>
    'AccessPriv' in n ? (n.AccessPriv.priv_name ?? '') : '',
  );
  // EXECUTE is the only privilege a function has, so revoking it is revoking everything.
  const allPrivileges =
    privs.length === 0 || (g.objtype === 'OBJECT_FUNCTION' && privs.includes('execute'));
  const roles = roleNames(g.grantees).filter((r) => ROLES_OF_INTEREST.has(r));
  if (roles.length === 0) return;
  const revoke = g.is_grant !== true;
  // Partial REVOKE (e.g. only INSERT) does not make a table private; only REVOKE ALL counts.
  if (revoke && !allPrivileges) return;
  const targets: { revoked: Set<string> }[] = [];
  if (g.targtype === 'ACL_TARGET_ALL_IN_SCHEMA') {
    const schemas = (g.objects ?? []).map((o) => ('String' in o ? (o.String.sval ?? '') : ''));
    if (g.objtype === 'OBJECT_TABLE')
      targets.push(...[...model.tables.values()].filter((t) => schemas.includes(t.schema)));
    if (g.objtype === 'OBJECT_FUNCTION')
      targets.push(...[...model.functions.values()].filter((f) => schemas.includes(f.schema)));
  } else {
    for (const o of g.objects ?? []) {
      if (g.objtype === 'OBJECT_TABLE' && 'RangeVar' in o) {
        const r = rel(o.RangeVar);
        const t = r ? model.tables.get(key(r.schema, r.name)) : undefined;
        if (t) targets.push(t);
      } else if (g.objtype === 'OBJECT_FUNCTION' && 'ObjectWithArgs' in o) {
        const f = model.functions.get(objKey(strings(o.ObjectWithArgs.objname)));
        if (f) targets.push(f);
      }
    }
  }
  for (const t of targets) {
    for (const r of roles) {
      if (revoke) t.revoked.add(r);
      else t.revoked.delete(r);
    }
  }
}

function objKey(parts: readonly string[]): string {
  const name = parts[parts.length - 1] ?? '';
  const schema = parts.length >= 2 ? (parts[parts.length - 2] ?? 'public') : 'public';
  return key(schema, name);
}

function newTable(r: { schema: string; name: string }, loc: Loc, uncertain: boolean): TableState {
  return {
    ...r,
    rls: false,
    force: false,
    created: loc,
    rlsLoc: undefined,
    policies: new Map(),
    revoked: new Set(),
    uncertain,
  };
}
