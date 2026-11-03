import { readFile } from 'node:fs/promises';
import ignore, { type Ignore } from 'ignore';

/**
 * A .gitignore (or exclude file) anchored at the directory that contains it.
 *
 * - `base`: that directory relative to the scan root ('' for the root itself).
 * - `prefix`: for scopes *above* the scan root (ancestor .gitignore files inside the same
 *   git repo), the scan root's path relative to the scope directory. Paths are evaluated
 *   as `prefix/relPath`.
 */
export type IgnoreScope =
  | { readonly kind: 'within'; readonly base: string; readonly matcher: Ignore }
  | { readonly kind: 'ancestor'; readonly prefix: string; readonly matcher: Ignore };

export async function loadIgnoreFile(absFile: string): Promise<Ignore | undefined> {
  let text: string;
  try {
    text = await readFile(absFile, 'utf8');
  } catch {
    return undefined;
  }
  return ignore({ allowRelativePaths: false }).add(text);
}

/**
 * Evaluate git-style ignore rules from multiple scopes, ordered outermost first. A deeper
 * scope's decision overrides a shallower one, and negations (`!foo`) re-include paths,
 * matching git's precedence for the common cases.
 */
export function isIgnoredByScopes(
  relPath: string,
  isDir: boolean,
  scopes: readonly IgnoreScope[],
): boolean {
  let ignored = false;
  for (const scope of scopes) {
    const local = localPath(scope, relPath);
    if (local === undefined || local === '') continue;
    const r = scope.matcher.test(isDir ? `${local}/` : local);
    if (r.ignored) ignored = true;
    else if (r.unignored) ignored = false;
  }
  return ignored;
}

function localPath(scope: IgnoreScope, relPath: string): string | undefined {
  if (scope.kind === 'ancestor') {
    return scope.prefix === '' ? relPath : `${scope.prefix}/${relPath}`;
  }
  if (scope.base === '') return relPath;
  if (relPath === scope.base) return '';
  return relPath.startsWith(`${scope.base}/`) ? relPath.slice(scope.base.length + 1) : undefined;
}
