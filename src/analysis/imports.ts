import path from 'node:path';
import ts from 'typescript';
import { CODE_KINDS } from '../core/discovery/file-kind.ts';
import type { FileRecord } from '../core/discovery/walker.ts';
import type { RuleContext } from '../core/engine/rule.ts';

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

/**
 * Resolve a local import specifier to a scanned file: relative paths (`./x`, `../x`) and the
 * near-universal aliases `@/x` and `~/x` (tried as `src/x` then `x`). Bare package specifiers
 * and other tsconfig paths are not resolved (no module resolution, by design: ADR-0010).
 */
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
    const noJs = base.replace(/\.(?:js|mjs|cjs)$/, ''); // ESM-style './x.js' pointing at x.ts
    for (const b of base === noJs ? [base] : [base, noJs]) {
      for (const ext of CODE_EXTENSIONS) {
        const f = ctx.file(`${b}${ext}`);
        if (f && CODE_KINDS.includes(f.kind)) return f;
      }
    }
  }
  return undefined;
}

export interface ImportBinding {
  /** Local name in the importing file. */
  readonly local: string;
  /** Exported name in the source module ('default' for default imports). */
  readonly imported: string;
  readonly spec: string;
}

/** Value bindings created by `import` declarations and simple `require()` destructuring. */
export function importBindings(sf: ts.SourceFile): ImportBinding[] {
  const out: ImportBinding[] = [];
  for (const s of sf.statements) {
    if (ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier)) {
      const clause = s.importClause;
      if (!clause || clause.phaseModifier === ts.SyntaxKind.TypeKeyword) continue;
      const spec = s.moduleSpecifier.text;
      if (clause.name) out.push({ local: clause.name.text, imported: 'default', spec });
      const nb = clause.namedBindings;
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) {
          if (el.isTypeOnly) continue;
          out.push({ local: el.name.text, imported: (el.propertyName ?? el.name).text, spec });
        }
      }
      if (nb && ts.isNamespaceImport(nb)) out.push({ local: nb.name.text, imported: '*', spec });
    }
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) {
        const init = d.initializer;
        if (
          !init ||
          !ts.isCallExpression(init) ||
          !ts.isIdentifier(init.expression) ||
          init.expression.text !== 'require'
        )
          continue;
        const arg = init.arguments[0];
        if (!arg || !ts.isStringLiteral(arg)) continue;
        if (ts.isIdentifier(d.name))
          out.push({ local: d.name.text, imported: 'default', spec: arg.text });
        if (ts.isObjectBindingPattern(d.name)) {
          for (const el of d.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const imported =
              el.propertyName && ts.isIdentifier(el.propertyName)
                ? el.propertyName.text
                : el.name.text;
            out.push({ local: el.name.text, imported, spec: arg.text });
          }
        }
      }
    }
  }
  return out;
}

/** Module specifiers imported (statically or via require) by the file. */
export function importedSpecifiers(sf: ts.SourceFile): Set<string> {
  return new Set(
    importBindings(sf)
      .map((b) => b.spec)
      .concat(
        sf.statements.flatMap((s) =>
          ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && !s.importClause
            ? [s.moduleSpecifier.text]
            : [],
        ),
      ),
  );
}
