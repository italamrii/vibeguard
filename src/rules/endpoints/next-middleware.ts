import path from 'node:path';
import ts from 'typescript';
import { staticName, stringValue, walk } from '../../analysis/ast-utils.ts';
import { resolveImport } from '../../analysis/imports.ts';
import { CODE_KINDS } from '../../core/discovery/file-kind.ts';
import type { RuleContext } from '../../core/engine/rule.ts';
import { bestAuth, type SignalAnalyzer } from './signals.ts';

/**
 * Next.js `middleware.ts` (renamed `proxy.ts` in Next 16) runs before matching routes. It
 * protects a route only if it (a) performs an auth check and (b) blocks or redirects when
 * that check fails, and (c) its `config.matcher` covers the route. The Supabase SSR template
 * calls `auth.getUser()` merely to refresh the session cookie; without a redirect/401 that
 * is not protection, and we do not treat it as such.
 */
export interface MiddlewareInfo {
  readonly dir: string; // project dir (posix, '' = root)
  readonly enforcesAuth: boolean;
  /**
   * Auth is attempted but cannot be confirmed: an auth helper we could not resolve, or a
   * blocking response we could not find because the logic lives in an unresolved import.
   */
  readonly authUnknown: boolean;
  readonly rateLimits: boolean;
  /** undefined = no matcher (runs on every route). */
  readonly matchers: readonly RegExp[] | undefined;
  /** A matcher entry could not be interpreted, so coverage is unknown. */
  readonly matcherUnknown: boolean;
}

const BLOCKS =
  /NextResponse\.redirect|Response\.redirect|\bredirect\(|status:\s*40[13]\b|new (?:Next)?Response\([^)]*40[13]/;

/** Convert a Next.js matcher source ('/api/:path*', '/((?!_next/static).*)') to a RegExp. */
export function matcherToRegExp(source: string): RegExp | undefined {
  // path-to-regexp semantics: `/:p*` is zero or more segments (so '/api/:path*' matches '/api'),
  // `/:p+` one or more, `/:p?` an optional segment.
  const converted = source
    .replace(/\/:(\w+)\*/g, '(?:/.*)?')
    .replace(/\/:(\w+)\+/g, '(?:/.+)')
    .replace(/\/:(\w+)\?/g, '(?:/[^/]+)?')
    .replace(/:(\w+)/g, '(?:[^/]+)');
  try {
    return new RegExp(`^${converted}/?$`);
  } catch {
    return undefined;
  }
}

export async function findMiddleware(
  ctx: RuleContext,
  signals: SignalAnalyzer,
): Promise<MiddlewareInfo[]> {
  const out: MiddlewareInfo[] = [];
  for (const file of ctx.files({
    kinds: CODE_KINDS,
    path: (p) => /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(p),
  })) {
    const parsed = await ctx.parseTs(file);
    const t = await ctx.readText(file);
    if (!parsed || !t) continue;
    const sf = parsed.sourceFile;
    const exported = sf.statements.filter((s) => !ts.isImportDeclaration(s));
    const analysis = await signals.analyse(file.relPath, sf, exported);
    // The blocking response may live in the helper the middleware calls (e.g. updateSession).
    let blocks = BLOCKS.test(t.text);
    let unresolvedLocal = false;
    if (!blocks) {
      for (const s of sf.statements) {
        if (!ts.isImportDeclaration(s) || !ts.isStringLiteral(s.moduleSpecifier)) continue;
        const spec = s.moduleSpecifier.text;
        const target = resolveImport(ctx, file.relPath, spec);
        if (!target && /^(?:\.|@\/|~\/)/.test(spec)) unresolvedLocal = true;
        const tt = target ? await ctx.readText(target) : undefined;
        if (tt && BLOCKS.test(tt.text)) blocks = true;
      }
    }
    let matchers: RegExp[] | undefined;
    let matcherUnknown = false;
    walk(sf, (n) => {
      if (ts.isPropertyAssignment(n) && staticName(n.name) === 'matcher') {
        const items = ts.isArrayLiteralExpression(n.initializer)
          ? [...n.initializer.elements]
          : [n.initializer];
        matchers = items.flatMap((e) => {
          const src = stringValue(e) ?? (ts.isObjectLiteralExpression(e) ? sourceOf(e) : undefined);
          const re = src !== undefined ? matcherToRegExp(src) : undefined;
          if (!re) matcherUnknown = true; // never assume coverage we cannot verify
          return re ? [re] : [];
        });
      }
      return undefined;
    });
    const dir = path.posix
      .dirname(file.relPath)
      .replace(/(?:^|\/)src$/, '')
      .replace(/^\.$/, '');
    const best = bestAuth(analysis);
    const enforcesAuth = best === 'strong' && blocks;
    out.push({
      dir,
      enforcesAuth,
      authUnknown:
        !enforcesAuth && (best === 'unverified' || (best === 'strong' && unresolvedLocal)),
      rateLimits: analysis.rateLimit.length > 0 || signals.fileUsesRateLimiter(sf),
      matchers,
      matcherUnknown,
    });
  }
  return out;
}

function sourceOf(o: ts.ObjectLiteralExpression): string | undefined {
  for (const p of o.properties) {
    if (ts.isPropertyAssignment(p) && staticName(p.name) === 'source')
      return stringValue(p.initializer);
  }
  return undefined;
}

export type Coverage = 'covers' | 'unknown' | 'none';

export function middlewareCoverage(mw: MiddlewareInfo, file: string, routePath: string): Coverage {
  if (mw.dir !== '' && !file.startsWith(`${mw.dir}/`)) return 'none';
  if (mw.matchers === undefined || mw.matchers.some((re) => re.test(routePath))) return 'covers';
  return mw.matcherUnknown ? 'unknown' : 'none';
}
