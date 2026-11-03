import path from 'node:path';
import ts from 'typescript';
import { CODE_KINDS } from '../core/discovery/file-kind.ts';
import type { RuleContext } from '../core/engine/rule.ts';
import { dottedName, hasDirective, staticName, stringValue, walk } from './ast-utils.ts';

/**
 * Server endpoints reachable over HTTP, found syntactically:
 *  - Next.js App Router route handlers   app/**\/route.ts  (exported GET/POST/…)
 *  - Next.js Pages Router API routes     pages/api/**      (default export)
 *  - Vercel serverless functions         api/**            (default export, non-Next projects)
 *  - Server actions                      'use server' modules (every exported function) and
 *                                        functions with an inline 'use server' directive
 *  - Express / Express Router            app.get('/x', …), router.route('/x').post(…)
 *  - Fastify                             fastify.get('/x', opts?, h), fastify.route({ … })
 */

export type EndpointKind =
  'next-route' | 'next-pages-api' | 'vercel-function' | 'server-action' | 'express' | 'fastify';

export interface Endpoint {
  readonly kind: EndpointKind;
  readonly file: string;
  readonly sf: ts.SourceFile;
  /** HTTP method in upper case; 'ANY' for catch-all handlers; 'ACTION' for server actions. */
  readonly method: string;
  /** URL path (best effort), or the function name for server actions. */
  readonly path: string;
  /** Node reported as the finding location. */
  readonly node: ts.Node;
  /** Handler function(s), when found in the file. */
  readonly handlers: readonly ts.Node[];
  /** Middleware passed on the route itself (Express args, Fastify preHandler/onRequest…). */
  readonly middleware: readonly ts.Node[];
  /** Middleware registered on the same app/router/instance that applies to this route. */
  readonly inherited: readonly ts.Node[];
}

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
const EXPRESS_METHODS = new Set([
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'del',
  'all',
  'options',
  'head',
]);
const FASTIFY_HOOKS = new Set(['onRequest', 'preParsing', 'preValidation', 'preHandler']);

const cache = new WeakMap<RuleContext, Promise<Endpoint[]>>();

export function findEndpoints(ctx: RuleContext): Promise<Endpoint[]> {
  let p = cache.get(ctx);
  if (!p) {
    p = extract(ctx);
    cache.set(ctx, p);
  }
  return p;
}

async function extract(ctx: RuleContext): Promise<Endpoint[]> {
  const out: Endpoint[] = [];
  const nextProject =
    ctx.files({ path: (p) => /(?:^|\/)next\.config\.[cm]?[jt]s$/.test(p) }).length > 0;
  for (const file of ctx.files({ kinds: CODE_KINDS })) {
    const t = await ctx.readText(file);
    if (!t) continue;
    const rel = file.relPath;
    const isRoute = /(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(rel);
    const isPagesApi = /(?:^|\/)pages\/api\//.test(rel);
    const isVercel =
      !nextProject &&
      /(?:^|\/)api\//.test(rel) &&
      !/(?:^|\/)(?:src|app|pages|lib|components)\//.test(rel.replace(/\/api\/.*$/, '/'));
    const mayHaveServer = /\b(?:express|Router|fastify|Fastify)\b/.test(t.text);
    const mayHaveActions = t.text.includes('use server');
    if (!isRoute && !isPagesApi && !isVercel && !mayHaveServer && !mayHaveActions) continue;
    const parsed = await ctx.parseTs(file);
    if (!parsed) continue;
    const sf = parsed.sourceFile;
    if (isRoute) out.push(...nextRouteHandlers(rel, sf));
    else if (isPagesApi || isVercel)
      out.push(...defaultExportHandler(rel, sf, isPagesApi ? 'next-pages-api' : 'vercel-function'));
    if (mayHaveActions) out.push(...serverActions(rel, sf));
    if (mayHaveServer) out.push(...expressAndFastify(rel, sf));
  }
  return out;
}

// --- Next.js ------------------------------------------------------------------------

export function appRouterPath(rel: string): string {
  const m = /(?:^|\/)app\/(.*)\/?route\.[cm]?[jt]sx?$/.exec(rel);
  const segs = (m?.[1] ?? '')
    .split('/')
    .filter((s) => s !== '' && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
  return `/${segs.join('/')}`;
}

function apiPath(rel: string): string {
  const m = /(?:^|\/)(?:pages\/)?(api\/.*)$/.exec(rel);
  return `/${(m?.[1] ?? rel).replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '')}`;
}

function isExported(node: ts.Node): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
  );
}

/** Same-file function (declaration or const arrow/function expression) by name. */
export function localFunction(sf: ts.SourceFile, name: string): ts.Node | undefined {
  for (const s of sf.statements) {
    if (ts.isFunctionDeclaration(s) && s.name?.text === name) return s;
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer)
          return unwrapHandler(d.initializer, sf);
      }
    }
  }
  return undefined;
}

/** Look through wrappers such as `withAuth(handler)` to the function, keeping the wrapper as middleware. */
function unwrapHandler(n: ts.Node, sf: ts.SourceFile): ts.Node {
  if (ts.isFunctionLike(n)) return n;
  if (ts.isIdentifier(n)) return localFunction(sf, n.text) ?? n;
  return n;
}

function nextRouteHandlers(rel: string, sf: ts.SourceFile): Endpoint[] {
  const out: Endpoint[] = [];
  const route = appRouterPath(rel);
  const add = (
    method: string,
    node: ts.Node,
    handler: ts.Node | undefined,
    wrapper?: ts.Node,
  ): void => {
    out.push({
      kind: 'next-route',
      file: rel,
      sf,
      method,
      path: route,
      node,
      handlers: handler ? [handler] : [],
      middleware: wrapper ? [wrapper] : [],
      inherited: [],
    });
  };
  for (const s of sf.statements) {
    if (
      ts.isFunctionDeclaration(s) &&
      isExported(s) &&
      s.name &&
      (HTTP_METHODS as readonly string[]).includes(s.name.text)
    ) {
      add(s.name.text, s, s);
    }
    if (ts.isVariableStatement(s) && isExported(s)) {
      for (const d of s.declarationList.declarations) {
        const name = ts.isIdentifier(d.name) ? d.name.text : '';
        if (!(HTTP_METHODS as readonly string[]).includes(name) || !d.initializer) continue;
        const [handler, wrapper] = splitWrapper(d.initializer, sf);
        add(name, s, handler, wrapper);
      }
    }
    // export { handler as GET, handler as POST }
    if (
      ts.isExportDeclaration(s) &&
      s.exportClause &&
      ts.isNamedExports(s.exportClause) &&
      !s.moduleSpecifier
    ) {
      for (const el of s.exportClause.elements) {
        if (!(HTTP_METHODS as readonly string[]).includes(el.name.text)) continue;
        const local = (el.propertyName ?? el.name).text;
        const fn = localFunction(sf, local);
        add(el.name.text, el, fn);
      }
    }
  }
  return out;
}

/** `withAuth(async (req) => …)` → [inner function, wrapper call]. */
function splitWrapper(
  init: ts.Expression,
  sf: ts.SourceFile,
): [ts.Node | undefined, ts.Node | undefined] {
  if (ts.isCallExpression(init)) {
    const inner = init.arguments.find((a) => ts.isFunctionLike(a) || ts.isIdentifier(a));
    return [inner ? unwrapHandler(inner, sf) : undefined, init];
  }
  return [unwrapHandler(init, sf), undefined];
}

function defaultExportHandler(
  rel: string,
  sf: ts.SourceFile,
  kind: 'next-pages-api' | 'vercel-function',
): Endpoint[] {
  for (const s of sf.statements) {
    let handler: ts.Node | undefined;
    let wrapper: ts.Node | undefined;
    if (
      ts.isFunctionDeclaration(s) &&
      isExported(s) &&
      (ts.getModifiers(s) ?? []).some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)
    ) {
      handler = s;
    } else if (ts.isExportAssignment(s) && !s.isExportEquals) {
      [handler, wrapper] = splitWrapper(s.expression, sf);
    } else {
      continue;
    }
    return [
      {
        kind,
        file: rel,
        sf,
        method: 'ANY',
        path: apiPath(rel),
        node: s,
        handlers: handler ? [handler] : [],
        middleware: wrapper ? [wrapper] : [],
        inherited: [],
      },
    ];
  }
  return [];
}

function serverActions(rel: string, sf: ts.SourceFile): Endpoint[] {
  const out: Endpoint[] = [];
  const moduleLevel = hasDirective(sf, 'use server');
  const add = (name: string, node: ts.Node, fn: ts.Node): void => {
    out.push({
      kind: 'server-action',
      file: rel,
      sf,
      method: 'ACTION',
      path: name,
      node,
      handlers: [fn],
      middleware: [],
      inherited: [],
    });
  };
  if (moduleLevel) {
    for (const s of sf.statements) {
      if (ts.isFunctionDeclaration(s) && isExported(s) && s.name) add(s.name.text, s, s);
      if (ts.isVariableStatement(s) && isExported(s)) {
        for (const d of s.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.initializer && ts.isFunctionLike(d.initializer))
            add(d.name.text, s, d.initializer);
        }
      }
    }
    return out;
  }
  // Inline actions: async function f() { 'use server'; … } inside components.
  walk(sf, (n) => {
    if (
      (ts.isFunctionDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n)) &&
      n.body &&
      ts.isBlock(n.body)
    ) {
      const first = n.body.statements[0];
      if (
        first &&
        ts.isExpressionStatement(first) &&
        ts.isStringLiteral(first.expression) &&
        first.expression.text === 'use server'
      ) {
        const name = ts.isFunctionDeclaration(n) ? (n.name?.text ?? 'action') : 'action';
        add(name, n, n);
      }
    }
    return undefined;
  });
  return out;
}

// --- Express / Fastify ----------------------------------------------------------------

const SERVER_FACTORY = /^(?:express|express\.Router|Router|fastify|Fastify|createServer)$/;
const SERVER_NAME = /^(?:app|server|api|router|routes?|fastify|instance)$|Router$/;

interface UseCall {
  readonly target: string;
  readonly pos: number;
  readonly prefix: string | undefined;
  readonly middleware: readonly ts.Node[];
}

/** Identifiers bound to express()/Router()/Fastify() in this file. */
function serverObjects(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  walk(sf, (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      let init: ts.Expression = n.initializer;
      while (ts.isAwaitExpression(init) || ts.isParenthesizedExpression(init))
        init = init.expression;
      if (ts.isCallExpression(init) && SERVER_FACTORY.test(dottedName(init.expression) ?? ''))
        names.add(n.name.text);
    }
    // Fastify plugins: async function routes(fastify, opts) { fastify.get(…) }
    if (
      ts.isParameter(n) &&
      ts.isIdentifier(n.name) &&
      /^(?:fastify|instance|app|server)$/.test(n.name.text)
    ) {
      names.add(n.name.text);
    }
    return undefined;
  });
  return names;
}

function routeTarget(expr: ts.Expression): { target: string; chainPath?: string } | undefined {
  // app.get(...)
  if (ts.isIdentifier(expr)) return { target: expr.text };
  // app.route('/x').get(...)   router.route('/x').get(...).post(...)
  if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
    const inner = expr.expression;
    if (inner.name.text === 'route') {
      const p = expr.arguments[0] ? stringValue(expr.arguments[0]) : undefined;
      const t = routeTarget(inner.expression);
      return t ? { target: t.target, ...(p !== undefined ? { chainPath: p } : {}) } : undefined;
    }
    if (EXPRESS_METHODS.has(inner.name.text)) return routeTarget(inner.expression);
  }
  return undefined;
}

function expressAndFastify(rel: string, sf: ts.SourceFile): Endpoint[] {
  const known = serverObjects(sf);
  const isServer = (name: string): boolean => known.has(name) || SERVER_NAME.test(name);
  const uses: UseCall[] = [];
  const hooks = new Map<string, ts.Node[]>(); // fastify instance → hooks
  const raw: { target: string; pos: number; ep: Omit<Endpoint, 'inherited'> }[] = [];

  walk(sf, (n) => {
    if (!ts.isCallExpression(n) || !ts.isPropertyAccessExpression(n.expression)) return undefined;
    const method = n.expression.name.text;
    const t = routeTarget(n.expression.expression);
    if (!t || !isServer(t.target)) return undefined;
    const args = [...n.arguments];

    if (method === 'use' || method === 'register') {
      const prefix = args[0] ? stringValue(args[0]) : undefined;
      uses.push({
        target: t.target,
        pos: n.getStart(sf),
        prefix,
        middleware: prefix === undefined ? args : args.slice(1),
      });
      return undefined;
    }
    if (method === 'addHook') {
      const name = args[0] ? stringValue(args[0]) : undefined;
      if (name && FASTIFY_HOOKS.has(name) && args[1])
        hooks.set(t.target, [...(hooks.get(t.target) ?? []), args[1]]);
      return undefined;
    }
    if (method === 'route' && args[0] && ts.isObjectLiteralExpression(args[0])) {
      // fastify.route({ method, url, preHandler, handler })
      const props = new Map(
        args[0].properties.flatMap((p) =>
          ts.isPropertyAssignment(p) ? [[staticName(p.name) ?? '', p.initializer] as const] : [],
        ),
      );
      const url = props.get('url') ?? props.get('path');
      const m = props.get('method');
      const handler = props.get('handler');
      if (!handler) return undefined;
      const methods =
        m && ts.isArrayLiteralExpression(m)
          ? m.elements.map((e) => stringValue(e) ?? 'ANY')
          : [m ? (stringValue(m) ?? 'ANY') : 'ANY'];
      for (const verb of methods) {
        raw.push({
          target: t.target,
          pos: n.getStart(sf),
          ep: {
            kind: 'fastify',
            file: rel,
            sf,
            method: verb.toUpperCase(),
            path: (url && stringValue(url)) ?? '?',
            node: n,
            handlers: [unwrapHandler(handler, sf)],
            middleware: [...FASTIFY_HOOKS].flatMap((h) => {
              const v = props.get(h);
              return v ? [v] : [];
            }),
          },
        });
      }
      return undefined;
    }
    if (!EXPRESS_METHODS.has(method)) return undefined;
    // Express: (path, ...middleware, handler). Fastify: (path, [opts], handler).
    const pathArg = t.chainPath !== undefined ? undefined : args.shift();
    const routePath = t.chainPath ?? (pathArg ? stringValue(pathArg) : undefined);
    if (routePath === undefined) return undefined; // app.get('setting') or non-route call
    if (args.length === 0) return undefined;
    const handler = args.pop();
    if (!handler) return undefined;
    const middleware: ts.Node[] = [];
    let kind: EndpointKind = 'express';
    for (const a of args) {
      if (ts.isObjectLiteralExpression(a)) {
        // Fastify route options: { preHandler, onRequest, schema, … }
        kind = 'fastify';
        for (const p of a.properties) {
          if (ts.isPropertyAssignment(p) && FASTIFY_HOOKS.has(staticName(p.name) ?? ''))
            middleware.push(p.initializer);
        }
      } else {
        middleware.push(a);
      }
    }
    if (
      /fastify|instance/i.test(t.target) ||
      /require\(['"]fastify['"]\)|from ['"]fastify['"]/.test(sf.text)
    )
      kind = 'fastify';
    raw.push({
      target: t.target,
      pos: n.getStart(sf),
      ep: {
        kind,
        file: rel,
        sf,
        method: method === 'all' ? 'ANY' : method === 'del' ? 'DELETE' : method.toUpperCase(),
        path: routePath,
        node: n,
        handlers: [unwrapHandler(handler, sf)],
        middleware,
      },
    });
    return undefined;
  });

  return raw.map(({ target, pos, ep }) => {
    // Express applies app.use() middleware registered *before* the route; Fastify hooks
    // apply to every route of the instance regardless of order.
    const inherited = uses
      .filter(
        (u) =>
          u.target === target &&
          u.pos < pos &&
          (u.prefix === undefined || pathCovered(u.prefix, ep.path)),
      )
      .flatMap((u) => u.middleware);
    return { ...ep, inherited: [...inherited, ...(hooks.get(target) ?? [])] };
  });
}

function pathCovered(prefix: string, routePath: string): boolean {
  const p = prefix.replace(/\/+$/, '');
  return p === '' || routePath === p || routePath.startsWith(`${p}/`) || !routePath.startsWith('/');
}

/** Directory of the package that owns a file (for locating middleware.ts). */
export function projectDirOf(rel: string): string {
  const m = /^(.*?)(?:\/)?(?:src\/)?(?:app|pages)\//.exec(rel);
  return m?.[1] ?? path.posix.dirname(rel);
}
