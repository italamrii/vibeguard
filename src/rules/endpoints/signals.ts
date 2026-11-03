import ts from 'typescript';
import { calleeName, dottedName, stringValue, walk } from '../../analysis/ast-utils.ts';
import { importBindings, resolveImport } from '../../analysis/imports.ts';
import { localFunction } from '../../analysis/routes.ts';
import type { RuleContext } from '../../core/engine/rule.ts';

/**
 * Syntactic signals inside endpoint handlers. We follow calls one level: into same-file
 * helpers and into functions imported from local modules (`./x`, `@/x`). Deeper call chains
 * are not followed (documented limitation).
 */

export type AccessKind = 'mutation' | 'read';
/** How data is reached: through RLS (user-scoped Supabase client) or around it. */
export type Privilege = 'privileged' | 'user-scoped' | 'direct';

export interface Sink {
  readonly kind: AccessKind;
  readonly api: string; // e.g. "supabase .delete()", "prisma.user.update", "Model.findByIdAndDelete"
  readonly privilege: Privilege;
}

const MUTATING =
  /^(?:insert|update|upsert|delete|remove|create|createMany|updateMany|deleteMany|save|set|add|destroy|bulkCreate|insertMany|insertOne|updateOne|deleteOne|replaceOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|increment|truncate|executeRaw|\$executeRaw|\$executeRawUnsafe|rpc)$/;
const PRISMA_READ =
  /^(?:findMany|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|count|aggregate|groupBy)$/;
const MONGOOSE_READ = /^(?:find|findOne|findById|countDocuments|aggregate|distinct|exists)$/;
const SUPABASE_QUERY = /^(?:select|insert|update|upsert|delete)$/;

export const AUTH_CALL =
  /^(?:auth|getServerSession|getSession|getUser|get\w*(?:User|Session|Viewer|Principal|Identity)|assert\w*(?:Auth|User|Session|Admin|Login|Signed)\w*|currentUser|getAuth|getToken|getKindeServerSession|validateRequest|validateSession|verifyIdToken|verifySessionCookie|jwtVerify|verify|authenticate\w*|authorize\w*|requireAuth\w*|require(?:User|Admin|Session|Login|Role|Auth)\w*|ensure\w*Auth\w*|ensureUser\w*|with\w*Auth\w*|isAuthenticated|isLoggedIn|isAdmin|checkAuth\w*|protect\w*|verify\w*(?:Token|Jwt|JWT|Session|Signature|User|Auth)\w*|constructEvent|constructEventAsync|passport\.authenticate|expressjwt|clerkMiddleware|requireAuth|getAuthUser|getCurrentUser\w*|getLoggedInUser\w*)$/;

export const RATE_LIMIT = /rate[_-]?limit|ratelimit|limiter|throttle|slowDown|arcjet/i;
const RATE_LIMIT_MODULES =
  /^(?:express-rate-limit|express-slow-down|@upstash\/ratelimit|rate-limiter-flexible|@fastify\/rate-limit|next-rate-limit|@arcjet\/[\w-]+|limiter|bottleneck)$/;
/** Managed auth providers that rate-limit credential endpoints themselves. */
const MANAGED_AUTH_CALL =
  /(?:\.auth\.(?:signInWithPassword|signInWithOtp|signUp|resetPasswordForEmail|verifyOtp|signInWithOAuth|exchangeCodeForSession|updateUser)|signInWithEmailAndPassword|createUserWithEmailAndPassword|sendPasswordResetEmail)$/;

/** Last segment of a callee: `supabase.auth.getUser` → `getUser`. */
function lastName(n: ts.Expression): string {
  const d = dottedName(n);
  if (d) return d.split('.').pop() ?? d;
  if (ts.isPropertyAccessExpression(n)) return n.name.text;
  if (ts.isCallExpression(n)) return lastName(n.expression);
  return '';
}

/** Receiver chain text for a call, through intermediate calls: supabase.from('x').select() → "supabase.from.select". */
function chain(n: ts.Expression): string[] {
  if (ts.isIdentifier(n)) return [n.text];
  if (n.kind === ts.SyntaxKind.ThisKeyword) return ['this'];
  if (ts.isPropertyAccessExpression(n)) return [...chain(n.expression), n.name.text];
  if (ts.isCallExpression(n)) return chain(n.expression);
  if (ts.isAwaitExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n))
    return chain(n.expression);
  return [];
}

export interface Analysis {
  sinks: Sink[];
  /** Names of auth signals found. */
  auth: string[];
  rateLimit: string[];
  managedAuth: boolean;
}

interface FileFacts {
  readonly privilege: Privilege;
}

/**
 * Whether a module's Supabase client is privileged (service role / secret key / admin SDK),
 * user-scoped (cookie/anon-key client, so RLS applies), or unknown/direct.
 */
function privilegeOfText(text: string): Privilege | undefined {
  if (
    /SERVICE[_-]?ROLE|SUPABASE_SECRET|SB_SECRET|firebase-admin|admin\.firestore\(|getFirestore\(\)/.test(
      text,
    )
  )
    return 'privileged';
  if (
    /@supabase\/ssr|@supabase\/auth-helpers|createServerClient|createRouteHandlerClient|createServerComponentClient|ANON_KEY|PUBLISHABLE_KEY/.test(
      text,
    )
  )
    return 'user-scoped';
  return undefined;
}

export class SignalAnalyzer {
  private readonly ctx: RuleContext;
  private readonly authNames: RegExp;
  private readonly rateNames: RegExp;
  private readonly factsCache = new Map<string, Promise<FileFacts>>();

  constructor(ctx: RuleContext) {
    this.ctx = ctx;
    const extraAuth = ctx.settings.endpoints.authFunctions;
    const extraRate = ctx.settings.endpoints.rateLimitFunctions;
    this.authNames =
      extraAuth.length > 0 ? new RegExp(`^(?:${extraAuth.map(escape).join('|')})$`) : /$^/;
    this.rateNames =
      extraRate.length > 0 ? new RegExp(`^(?:${extraRate.map(escape).join('|')})$`) : /$^/;
  }

  isAuthName(name: string, full = name): boolean {
    return (
      AUTH_CALL.test(name) ||
      AUTH_CALL.test(full) ||
      this.authNames.test(name) ||
      this.authNames.test(full)
    );
  }

  isRateLimitName(name: string): boolean {
    return RATE_LIMIT.test(name) || this.rateNames.test(name);
  }

  /** Privilege of Supabase/Firebase access in a file, following one level of imports. */
  private facts(file: string, sf: ts.SourceFile): Promise<FileFacts> {
    let p = this.factsCache.get(file);
    if (!p) {
      p = (async () => {
        const own = privilegeOfText(sf.text);
        if (own === 'privileged') return { privilege: 'privileged' };
        let best: Privilege | undefined = own;
        for (const b of importBindings(sf)) {
          const target = resolveImport(this.ctx, file, b.spec);
          const t = target ? await this.ctx.readText(target) : undefined;
          const pv = t ? privilegeOfText(t.text) : undefined;
          if (pv === 'privileged') return { privilege: 'privileged' };
          if (pv === 'user-scoped') best = 'user-scoped';
        }
        return { privilege: best ?? 'direct' };
      })();
      this.factsCache.set(file, p);
    }
    return p;
  }

  /**
   * Analyse handler bodies plus middleware nodes. `depth` limits helper following to one
   * level (same-file helpers and local imported functions).
   */
  async analyse(
    file: string,
    sf: ts.SourceFile,
    nodes: readonly ts.Node[],
    depth = 1,
  ): Promise<Analysis> {
    const result: Analysis = { sinks: [], auth: [], rateLimit: [], managedAuth: false };
    const facts = await this.facts(file, sf);
    const followed: { file: string; sf: ts.SourceFile; node: ts.Node }[] = [];
    const bindings = depth > 0 ? importBindings(sf) : [];

    for (const root of nodes) {
      // A middleware passed by reference: `requireAuth`, `fastify.authenticate`, `limiter`.
      if (ts.isIdentifier(root) || ts.isPropertyAccessExpression(root)) {
        const name = lastName(root);
        const full = dottedName(root) ?? name;
        if (this.isAuthName(name, full)) result.auth.push(full);
        if (this.isRateLimitName(full)) result.rateLimit.push(full);
        const def = depth > 0 && ts.isIdentifier(root) ? localFunction(sf, root.text) : undefined;
        if (def && !nodes.includes(def)) followed.push({ file, sf, node: def });
      }
      walk(root, (n) => {
        if (ts.isArrayLiteralExpression(n) || ts.isIdentifier(n)) {
          if (ts.isIdentifier(n) && n !== root && isMiddlewareReference(n)) {
            if (this.isAuthName(n.text)) result.auth.push(n.text);
            if (this.isRateLimitName(n.text)) result.rateLimit.push(n.text);
            // `const guard = rateLimit({...}); app.post('/login', guard, h)`: look at the definition.
            const def = depth > 0 ? localFunction(sf, n.text) : undefined;
            if (def && !nodes.includes(def)) followed.push({ file, sf, node: def });
          }
          return undefined;
        }
        // `fastify.authenticate` / `auth.required` passed as middleware (not called).
        if (ts.isPropertyAccessExpression(n) && n !== root && isMiddlewareReference(n)) {
          const full = dottedName(n) ?? n.name.text;
          if (this.isAuthName(n.name.text, full)) result.auth.push(full);
          if (this.isRateLimitName(full)) result.rateLimit.push(full);
        }
        // Plugins registered by module name: register(require('@fastify/rate-limit')), import('…').
        if (ts.isStringLiteral(n) && RATE_LIMIT_MODULES.test(n.text)) result.rateLimit.push(n.text);
        if (ts.isBinaryExpression(n) && isSecretHeaderComparison(n))
          result.auth.push('header secret check');
        if (!ts.isCallExpression(n) && !ts.isTaggedTemplateExpression(n)) return undefined;

        if (ts.isTaggedTemplateExpression(n)) {
          // sql`…` (postgres.js, Neon, Vercel Postgres), db.sql`…`, getSql()`…`, prisma.$queryRaw`…`
          const tag = n.tag.getText(sf).replace(/\s+/g, '');
          if (/^(?:\w+\.)?sql$|^\w*[sS]ql\(\)$|\.\$(?:queryRaw|executeRaw)(?:Unsafe)?$/.test(tag)) {
            const kind = sqlKind(n.template.getText(sf));
            result.sinks.push({ kind, api: `${tag}\`…\``, privilege: 'direct' });
          }
          return undefined;
        }

        const name = lastName(n.expression);
        const full = calleeName(n) ?? name;
        const parts = chain(n.expression);
        if (this.isAuthName(name, full)) result.auth.push(full);
        if (this.isRateLimitName(full)) result.rateLimit.push(full);
        if (MANAGED_AUTH_CALL.test(full)) result.managedAuth = true;
        const sink = sinkOf(parts, name, n);
        if (sink) {
          const privilege: Privilege = sink.supabaseOrFirebase ? facts.privilege : 'direct';
          result.sinks.push({ kind: sink.kind, api: sink.api, privilege });
        }
        // Follow one level into same-file helpers (imported helpers are resolved below).
        if (depth > 0 && ts.isIdentifier(n.expression)) {
          const local = localFunction(sf, n.expression.text);
          if (local && !nodes.includes(local)) followed.push({ file, sf, node: local });
        }
        return undefined;
      });
    }

    // Imported helpers: resolve and analyse their exported function bodies (one level).
    for (const root of nodes) {
      const called = new Set<string>();
      walk(root, (n) => {
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) called.add(n.expression.text);
        if (ts.isIdentifier(n) && isMiddlewareReference(n)) called.add(n.text);
        return undefined;
      });
      for (const b of bindings.filter((x) => called.has(x.local))) {
        const target = resolveImport(this.ctx, file, b.spec);
        const parsed = target ? await this.ctx.parseTs(target) : undefined;
        if (!target || !parsed) continue;
        const fn =
          b.imported === 'default'
            ? defaultExportFunction(parsed.sourceFile)
            : localFunction(parsed.sourceFile, b.imported);
        if (fn) followed.push({ file: target.relPath, sf: parsed.sourceFile, node: fn });
      }
    }

    for (const f of followed) {
      const sub = await this.analyse(f.file, f.sf, [f.node], depth - 1);
      result.sinks.push(...sub.sinks);
      result.auth.push(...sub.auth);
      result.rateLimit.push(...sub.rateLimit);
      if (sub.managedAuth) result.managedAuth = true;
    }
    return result;
  }

  /** Rate limiting configured in a file at module level (e.g. a limiter imported and applied). */
  fileUsesRateLimiter(sf: ts.SourceFile): boolean {
    return (
      importBindings(sf).some((b) => RATE_LIMIT_MODULES.test(b.spec)) ||
      sf.statements.some(
        (s) =>
          ts.isImportDeclaration(s) &&
          ts.isStringLiteral(s.moduleSpecifier) &&
          RATE_LIMIT_MODULES.test(s.moduleSpecifier.text),
      )
    );
  }
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Identifier used as a value (middleware passed to a route), not called and not declared. */
function isMiddlewareReference(n: ts.Expression): boolean {
  const p = n.parent;
  return (
    (ts.isCallExpression(p) && p.arguments.includes(n)) ||
    ts.isArrayLiteralExpression(p) ||
    (ts.isPropertyAssignment(p) && p.initializer === n)
  );
}

/** `req.headers['x-api-key'] === process.env.X`, `authorization !== \`Bearer ${process.env.CRON_SECRET}\`` */
function isSecretHeaderComparison(n: ts.BinaryExpression): boolean {
  const op = n.operatorToken.kind;
  if (
    ![
      ts.SyntaxKind.EqualsEqualsEqualsToken,
      ts.SyntaxKind.ExclamationEqualsEqualsToken,
      ts.SyntaxKind.EqualsEqualsToken,
      ts.SyntaxKind.ExclamationEqualsToken,
    ].includes(op)
  )
    return false;
  const text = `${n.left.getText()} ${n.right.getText()}`;
  return (
    /process\.env\.[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)/.test(text) &&
    /header|authorization|x-[\w-]*(?:key|token|secret)|bearer|token|secret/i.test(text)
  );
}

function defaultExportFunction(sf: ts.SourceFile): ts.Node | undefined {
  for (const s of sf.statements) {
    if (
      ts.isFunctionDeclaration(s) &&
      (ts.getModifiers(s) ?? []).some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)
    )
      return s;
    if (ts.isExportAssignment(s) && ts.isIdentifier(s.expression))
      return localFunction(sf, s.expression.text);
    if (ts.isExportAssignment(s) && ts.isFunctionLike(s.expression)) return s.expression;
  }
  return undefined;
}

const SQL_STATEMENT = /^\s*(?:with|select|insert|update|delete|replace|upsert|merge)\b/i;

/** SQL text of a string or template literal argument, if it looks like a statement. */
function sqlTextOf(n: ts.Node): string | undefined {
  const text =
    stringValue(n) ?? (ts.isTemplateExpression(n) ? n.getText().slice(1, -1) : undefined);
  return text !== undefined && SQL_STATEMENT.test(text) ? text : undefined;
}

function sqlKind(text: string): AccessKind {
  return /\b(?:insert|update|delete|replace|upsert|merge|drop|alter|truncate)\b/i.test(text)
    ? 'mutation'
    : 'read';
}

interface RawSink {
  readonly kind: AccessKind;
  readonly api: string;
  readonly supabaseOrFirebase: boolean;
}

function sinkOf(
  parts: readonly string[],
  method: string,
  call: ts.CallExpression,
): RawSink | undefined {
  const joined = parts.join('.');
  // Supabase: x.from('t').select()/insert()/…, x.rpc('fn'), x.storage.from('b').upload/remove
  if (parts.includes('from') && SUPABASE_QUERY.test(method) && !parts.includes('storage')) {
    return {
      kind: method === 'select' ? 'read' : 'mutation',
      api: `supabase .${method}()`,
      supabaseOrFirebase: true,
    };
  }
  if (method === 'rpc' && parts.length >= 2)
    return { kind: 'mutation', api: 'supabase .rpc()', supabaseOrFirebase: true };
  if (parts.includes('storage') && /^(?:upload|remove|move|update|copy)$/.test(method)) {
    return { kind: 'mutation', api: `supabase storage .${method}()`, supabaseOrFirebase: true };
  }
  // Firestore (admin or client SDK): collection(...).doc(...).set/update/delete/get, add
  if (
    (parts.includes('collection') || parts.includes('doc')) &&
    /^(?:get|set|update|delete|add|create)$/.test(method)
  ) {
    return {
      kind: method === 'get' ? 'read' : 'mutation',
      api: `firestore .${method}()`,
      supabaseOrFirebase: true,
    };
  }
  // Prisma: prisma.model.op / db.model.op
  if (parts.length === 3 && /^(?:prisma|db|client)$/.test(parts[0] ?? '')) {
    if (PRISMA_READ.test(method)) return { kind: 'read', api: joined, supabaseOrFirebase: false };
    if (MUTATING.test(method)) return { kind: 'mutation', api: joined, supabaseOrFirebase: false };
  }
  if (
    parts.length === 2 &&
    parts[0] === 'prisma' &&
    /^\$(?:queryRaw|queryRawUnsafe|executeRaw|executeRawUnsafe)$/.test(method)
  ) {
    return {
      kind: method.startsWith('$query') ? 'read' : 'mutation',
      api: joined,
      supabaseOrFirebase: false,
    };
  }
  // Drizzle: db.select().from(t), db.insert(t).values(), db.update(t).set(), db.delete(t), db.query.t.findMany()
  const root = parts[0] ?? '';
  if (/^(?:db|database|drizzle|tx)$/.test(root)) {
    const op = parts[1] ?? '';
    if (/^(?:insert|update|delete)$/.test(op))
      return { kind: 'mutation', api: `drizzle ${root}.${op}()`, supabaseOrFirebase: false };
    if (
      op === 'select' ||
      op === 'selectDistinct' ||
      (op === 'query' && /^find(?:Many|First)$/.test(method))
    ) {
      return { kind: 'read', api: `drizzle ${root}.${op}()`, supabaseOrFirebase: false };
    }
    if (op === 'execute' || method === 'execute')
      return { kind: 'mutation', api: `${root}.execute()`, supabaseOrFirebase: false };
  }
  // Mongoose / Sequelize-style models: User.find(), Order.findByIdAndDelete()
  if (
    parts.length === 2 &&
    /^[A-Z][A-Za-z0-9]*$/.test(root) &&
    !/^(?:Object|Array|JSON|Math|Promise|Response|NextResponse|Date|Number|String|Buffer|URL|Reflect|Intl|Symbol|Error|Map|Set)$/.test(
      root,
    )
  ) {
    if (MONGOOSE_READ.test(method))
      return { kind: 'read', api: `${root}.${method}()`, supabaseOrFirebase: false };
    if (MUTATING.test(method))
      return { kind: 'mutation', api: `${root}.${method}()`, supabaseOrFirebase: false };
  }
  // Prepared statements: Cloudflare D1 / better-sqlite3 / libSQL: x.prepare('SQL').bind(…).run()
  if ((method === 'prepare' || method === 'exec') && call.arguments[0]) {
    const text = sqlTextOf(call.arguments[0]);
    if (text !== undefined)
      return { kind: sqlKind(text), api: `.${method}(SQL)`, supabaseOrFirebase: false };
  }
  // pg / mysql / knex raw queries: pool.query('…'), client.query(…), db.query(…)
  if (method === 'query' && /^(?:pool|client|db|conn|connection|pg|mysql|sql)$/.test(root)) {
    const first = call.arguments[0];
    const text = first ? (stringValue(first) ?? first.getText()) : '';
    return { kind: sqlKind(text), api: `${root}.query()`, supabaseOrFirebase: false };
  }
  return undefined;
}
