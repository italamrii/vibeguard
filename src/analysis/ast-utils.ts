import ts from 'typescript';

/** Depth-first pre-order traversal. Return `false` from `visit` to skip a subtree. */
export function walk(node: ts.Node, visit: (n: ts.Node) => boolean | undefined): void {
  if (visit(node) === false) return;
  ts.forEachChild(node, (child) => {
    walk(child, visit);
  });
}

/** Text of a static property / binding name, or undefined for computed names. */
export function staticName(name: ts.Node | undefined): string | undefined {
  if (!name) return undefined;
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return name.text;
  if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) {
    return name.expression.text;
  }
  return undefined;
}

/** The value of a string literal or a template literal without substitutions. */
export function stringValue(node: ts.Node): string | undefined {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
    ? node.text
    : undefined;
}

/** Dotted text of an expression like `process.env.X` or `import.meta.env`; undefined if not a plain chain. */
export function dottedName(node: ts.Node): string | undefined {
  if (ts.isIdentifier(node)) return node.text;
  if (node.kind === ts.SyntaxKind.ThisKeyword) return 'this';
  if (ts.isMetaProperty(node)) {
    return `${ts.tokenToString(node.keywordToken) ?? ''}.${node.name.text}`;
  }
  if (ts.isPropertyAccessExpression(node)) {
    const left = dottedName(node.expression);
    return left === undefined ? undefined : `${left}.${node.name.text}`;
  }
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
    const left = dottedName(node.expression);
    return left === undefined ? undefined : `${left}.${node.argumentExpression.text}`;
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node)
  ) {
    return dottedName(node.expression);
  }
  return undefined;
}

/** Name of the called function, e.g. `jwt.sign` for `jwt.sign(a, b)`. */
export function calleeName(call: ts.CallExpression | ts.NewExpression): string | undefined {
  return dottedName(call.expression);
}

/**
 * The "name" a string literal is bound to, from its syntactic context:
 * `const apiKey = '…'`, `{ apiKey: '…' }`, `cfg.apiKey = '…'`, `<X apiKey="…" />`,
 * `function f(apiKey = '…')`. Returns undefined when there is no binding name.
 */
export function bindingNameOf(literal: ts.Node): string | undefined {
  let node: ts.Node = literal;
  let parent = node.parent;
  // Look through `as const`, parentheses, `satisfies`, and `x ?? '…'` / `x || '…'` defaults.
  while (
    ts.isAsExpression(parent) ||
    ts.isParenthesizedExpression(parent) ||
    ts.isSatisfiesExpression(parent) ||
    (ts.isBinaryExpression(parent) &&
      parent.right === node &&
      (parent.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
        parent.operatorToken.kind === ts.SyntaxKind.BarBarToken))
  ) {
    // `process.env.JWT_SECRET || 'fallback'`: the env var names the value better than
    // whatever the expression is assigned to.
    if (ts.isBinaryExpression(parent)) {
      const env = /^(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(
        dottedName(parent.left) ?? '',
      );
      if (env?.[1] !== undefined) return env[1];
    }
    node = parent;
    parent = parent.parent;
  }
  if (ts.isVariableDeclaration(parent) && parent.initializer === node)
    return staticName(parent.name);
  if (ts.isPropertyAssignment(parent) && parent.initializer === node)
    return staticName(parent.name);
  if (ts.isPropertyDeclaration(parent) && parent.initializer === node)
    return staticName(parent.name);
  if (ts.isParameter(parent) && parent.initializer === node) return staticName(parent.name);
  if (ts.isBindingElement(parent) && parent.initializer === node) return staticName(parent.name);
  if (ts.isJsxAttribute(parent)) return staticName(parent.name);
  if (ts.isJsxExpression(parent) && ts.isJsxAttribute(parent.parent))
    return staticName(parent.parent.name);
  if (
    ts.isBinaryExpression(parent) &&
    parent.right === node &&
    parent.operatorToken.kind === ts.SyntaxKind.EqualsToken
  ) {
    const left = parent.left;
    if (ts.isIdentifier(left)) return left.text;
    if (ts.isPropertyAccessExpression(left)) return left.name.text;
    if (ts.isElementAccessExpression(left)) return staticName(left.argumentExpression);
  }
  return undefined;
}

/** True when the file starts with a `"use client"` / `"use server"` directive. */
export function hasDirective(sf: ts.SourceFile, directive: 'use client' | 'use server'): boolean {
  for (const stmt of sf.statements) {
    if (!ts.isExpressionStatement(stmt) || !ts.isStringLiteral(stmt.expression)) return false;
    if (stmt.expression.text === directive) return true;
  }
  return false;
}
