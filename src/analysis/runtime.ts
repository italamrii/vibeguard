import path from 'node:path';
import ts from 'typescript';
import type { FileRecord } from '../core/discovery/walker.ts';
import type { RuleContext } from '../core/engine/rule.ts';
import type { Confidence } from '../core/findings/severity.ts';
import { dottedName, hasDirective, walk } from './ast-utils.ts';

/**
 * Where a module runs: shipped to the browser ('client'), only on a server ('server'),
 * or not determinable without an import graph ('unknown'). See docs/adr/0010.
 *
 * Signals, strongest first:
 *  1. `'use client'` / `'use server'` directives; `import 'client-only' | 'server-only'`.
 *  2. Server-only locations: API routes, route handlers, middleware, `*.server.*`,
 *     `server/`, `api/`, `supabase/functions/`, `netlify/functions/`, scripts, configs.
 *  3. Framework conventions from the nearest package.json:
 *     - Next.js App Router: files under `app/` are Server Components by default (server);
 *       Pages Router pages are bundled for the browser (client, medium confidence).
 *     - Vite / Create React App / Expo: `src/` (Expo: `app/`) is browser code.
 *  4. Use of `import.meta.env.VITE_*` (only meaningful in a Vite client bundle).
 * Anything else is 'unknown' and rules must not report client-only problems for it.
 */
export type Runtime = 'client' | 'server' | 'unknown';

export interface RuntimeVerdict {
  readonly runtime: Runtime;
  readonly confidence: Confidence;
  readonly reason: string;
}

type Framework = 'next' | 'vite' | 'cra' | 'expo' | 'none';

interface PackageInfo {
  readonly dir: string; // posix, relative to root ('' for root)
  readonly framework: Framework;
}

const SERVER_PATH =
  /(?:^|\/)(?:api|server|servers|backend|functions|lambda|lambdas|scripts|cron|workers?|prisma|migrations)\/|(?:^|\/)(?:supabase\/functions|netlify\/functions|pages\/api|src\/pages\/api)\/|(?:^|\/)middleware\.[cm]?[jt]s$|(?:^|\/)route\.[cm]?[jt]s$|\.server\.[cm]?[jt]sx?$|(?:^|\/)(?:next|vite|nuxt|astro|svelte|tailwind|postcss|eslint|vitest|jest|playwright)\.config\.[cm]?[jt]s$/;

const pkgCache = new WeakMap<RuleContext, Map<string, Promise<PackageInfo>>>();

async function packageFor(ctx: RuleContext, relPath: string): Promise<PackageInfo> {
  let perCtx = pkgCache.get(ctx);
  if (!perCtx) {
    perCtx = new Map();
    pkgCache.set(ctx, perCtx);
  }
  let dir = path.posix.dirname(relPath);
  for (;;) {
    const d = dir === '.' ? '' : dir;
    const pkgPath = d === '' ? 'package.json' : `${d}/package.json`;
    const file = ctx.file(pkgPath);
    if (file) {
      let p = perCtx.get(pkgPath);
      if (!p) {
        p = readPackage(ctx, file, d);
        perCtx.set(pkgPath, p);
      }
      return p;
    }
    if (d === '') return { dir: '', framework: 'none' };
    dir = path.posix.dirname(d);
  }
}

async function readPackage(ctx: RuleContext, file: FileRecord, dir: string): Promise<PackageInfo> {
  const t = await ctx.readText(file);
  let deps: Record<string, unknown> = {};
  try {
    const pkg = JSON.parse(t?.text ?? '{}') as {
      dependencies?: Record<string, unknown>;
      devDependencies?: Record<string, unknown>;
    };
    deps = { ...pkg.devDependencies, ...pkg.dependencies };
  } catch {
    // unparseable package.json: framework unknown
  }
  const framework: Framework =
    'next' in deps
      ? 'next'
      : 'expo' in deps
        ? 'expo'
        : 'react-scripts' in deps
          ? 'cra'
          : 'vite' in deps
            ? 'vite'
            : 'none';
  return { dir, framework };
}

function imports(sf: ts.SourceFile, spec: string): boolean {
  return sf.statements.some(
    (s) =>
      ts.isImportDeclaration(s) &&
      ts.isStringLiteral(s.moduleSpecifier) &&
      s.moduleSpecifier.text === spec,
  );
}

function usesViteClientEnv(sf: ts.SourceFile): boolean {
  let found = false;
  walk(sf, (n) => {
    if (found) return false;
    if (ts.isPropertyAccessExpression(n) && dottedName(n)?.startsWith('import.meta.env.VITE_'))
      found = true;
    return undefined;
  });
  return found;
}

export async function classifyRuntime(
  ctx: RuleContext,
  file: FileRecord,
  sf: ts.SourceFile,
): Promise<RuntimeVerdict> {
  if (hasDirective(sf, 'use client'))
    return { runtime: 'client', confidence: 'high', reason: "'use client'" };
  if (hasDirective(sf, 'use server'))
    return { runtime: 'server', confidence: 'high', reason: "'use server'" };
  if (imports(sf, 'server-only'))
    return { runtime: 'server', confidence: 'high', reason: "import 'server-only'" };
  if (imports(sf, 'client-only'))
    return { runtime: 'client', confidence: 'high', reason: "import 'client-only'" };

  const pkg = await packageFor(ctx, file.relPath);
  const local = pkg.dir === '' ? file.relPath : file.relPath.slice(pkg.dir.length + 1);
  if (SERVER_PATH.test(local))
    return { runtime: 'server', confidence: 'high', reason: 'server-only location' };

  switch (pkg.framework) {
    case 'next':
      if (/^(?:src\/)?app\//.test(local)) {
        return {
          runtime: 'server',
          confidence: 'medium',
          reason: 'Next.js App Router (Server Component by default)',
        };
      }
      if (/^(?:src\/)?pages\//.test(local)) {
        return {
          runtime: 'client',
          confidence: 'medium',
          reason: 'Next.js Pages Router page (bundled for the browser)',
        };
      }
      break;
    case 'vite':
    case 'cra':
      if (/^src\//.test(local))
        return {
          runtime: 'client',
          confidence: 'high',
          reason: `${pkg.framework === 'vite' ? 'Vite' : 'Create React App'} src/`,
        };
      break;
    case 'expo':
      if (/^(?:src|app)\//.test(local))
        return { runtime: 'client', confidence: 'high', reason: 'Expo app code' };
      break;
    case 'none':
      break;
  }
  if (usesViteClientEnv(sf))
    return { runtime: 'client', confidence: 'medium', reason: 'uses import.meta.env.VITE_*' };
  return { runtime: 'unknown', confidence: 'low', reason: 'no client/server signal' };
}
