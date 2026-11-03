import type { Node } from 'libpg-query';

/**
 * Who a policy expression lets through, judged syntactically:
 *  - 'true':          every row, for everyone the policy applies to (`USING (true)`, `1 = 1`)
 *  - 'authenticated': every row, for anyone who is logged in (`auth.uid() IS NOT NULL`,
 *                     `auth.role() = 'authenticated'`): no row ownership check
 *  - 'scoped':        anything else (references a column, a subquery, a claim value, …).
 *                     We do not try to prove scoped expressions safe; they are not reported.
 */
export type Reach = 'true' | 'authenticated' | 'scoped';

function names(list: readonly Node[] | undefined): string[] {
  return (list ?? []).map((n) => ('String' in n ? (n.String.sval ?? '') : ''));
}

function isFunc(n: Node, schema: string, name: string): boolean {
  if (!('FuncCall' in n)) return false;
  const parts = names(n.FuncCall.funcname);
  return (
    parts.length === 2 &&
    parts[0] === schema &&
    parts[1] === name &&
    (n.FuncCall.args ?? []).length === 0
  );
}

/** `(select auth.uid())`: the recommended, cached form in Supabase docs. */
function unwrapScalarSubquery(n: Node): Node {
  if ('SubLink' in n && n.SubLink.subLinkType === 'EXPR_SUBLINK') {
    const sel = n.SubLink.subselect;
    if (sel && 'SelectStmt' in sel) {
      const t = sel.SelectStmt.targetList ?? [];
      const only = t.length === 1 ? t[0] : undefined;
      if (only && 'ResTarget' in only && only.ResTarget.val && !sel.SelectStmt.fromClause) {
        return only.ResTarget.val;
      }
    }
  }
  return n;
}

function constString(n: Node): string | undefined {
  if ('A_Const' in n) return n.A_Const.sval?.sval;
  if ('TypeCast' in n && n.TypeCast.arg) return constString(n.TypeCast.arg);
  return undefined;
}

function operator(n: Node): string | undefined {
  return 'A_Expr' in n && n.A_Expr.kind === 'AEXPR_OP' ? names(n.A_Expr.name).join('.') : undefined;
}

export function isAlwaysTrue(n: Node): boolean {
  if ('A_Const' in n) return n.A_Const.boolval?.boolval === true;
  if ('TypeCast' in n && n.TypeCast.arg) {
    const s = constString(n.TypeCast.arg);
    const type = names(n.TypeCast.typeName?.names).pop();
    return (type === 'bool' || type === 'boolean') && (s === 'true' || s === 't');
  }
  if ('BoolExpr' in n) {
    const args = n.BoolExpr.args ?? [];
    if (n.BoolExpr.boolop === 'OR_EXPR') return args.some(isAlwaysTrue);
    if (n.BoolExpr.boolop === 'AND_EXPR') return args.length > 0 && args.every(isAlwaysTrue);
    return false;
  }
  if (operator(n) === '=' && 'A_Expr' in n && n.A_Expr.lexpr && n.A_Expr.rexpr) {
    const l = n.A_Expr.lexpr;
    const r = n.A_Expr.rexpr;
    if ('A_Const' in l && 'A_Const' in r)
      return (
        JSON.stringify(l.A_Const.ival ?? l.A_Const.sval) ===
          JSON.stringify(r.A_Const.ival ?? r.A_Const.sval) &&
        (l.A_Const.ival ?? l.A_Const.sval) !== undefined
      );
  }
  return false;
}

/** auth.role(), or auth.jwt() ->> 'role' */
function isRoleExpr(n: Node): boolean {
  const u = unwrapScalarSubquery(n);
  if (isFunc(u, 'auth', 'role')) return true;
  if (operator(u) === '->>' && 'A_Expr' in u && u.A_Expr.lexpr && u.A_Expr.rexpr) {
    return (
      isFunc(unwrapScalarSubquery(u.A_Expr.lexpr), 'auth', 'jwt') &&
      constString(u.A_Expr.rexpr) === 'role'
    );
  }
  return false;
}

/** A row-independent check that only asks "is the caller logged in?". */
export function isAuthenticatedOnly(n: Node): boolean {
  if ('NullTest' in n && n.NullTest.nulltesttype === 'IS_NOT_NULL' && n.NullTest.arg) {
    return isFunc(unwrapScalarSubquery(n.NullTest.arg), 'auth', 'uid');
  }
  if (operator(n) === '=' && 'A_Expr' in n && n.A_Expr.lexpr && n.A_Expr.rexpr) {
    const { lexpr, rexpr } = n.A_Expr;
    return (
      (isRoleExpr(lexpr) && constString(rexpr) === 'authenticated') ||
      (isRoleExpr(rexpr) && constString(lexpr) === 'authenticated')
    );
  }
  if ('BoolExpr' in n) {
    const args = n.BoolExpr.args ?? [];
    const ok = (a: Node): boolean => isAuthenticatedOnly(a) || isAlwaysTrue(a);
    if (n.BoolExpr.boolop === 'AND_EXPR')
      return args.length > 0 && args.every(ok) && args.some(isAuthenticatedOnly);
    if (n.BoolExpr.boolop === 'OR_EXPR') return args.length > 0 && args.every(ok);
  }
  return false;
}

export function reachOf(n: Node | undefined): Reach | undefined {
  if (!n) return undefined;
  if (isAlwaysTrue(n)) return 'true';
  if (isAuthenticatedOnly(n)) return 'authenticated';
  return 'scoped';
}
