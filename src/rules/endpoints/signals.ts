import ts from 'typescript';
import { dottedName, stringValue, walk } from '../../analysis/ast-utils.ts';
import { importBindings, resolveImport, type ImportBinding } from '../../analysis/imports.ts';
import { localFunction } from '../../analysis/routes.ts';
import type { RuleContext } from '../../core/engine/rule.ts';
import { findSecrets } from '../secrets/patterns.ts';

/**
 * Syntactic signals inside endpoint handlers (ADR-0012). Calls are followed ONE level: into
 * same-file helpers and into functions imported from local modules (`./x`, `@/x`).
 *
 * Authentication is three-valued on purpose: false positives are this family's biggest
 * risk, so "we could not tell" must never collapse into either "protected" or "open".
 *  - strong:      a recognised auth API (Supabase getUser, Auth.js, Clerk, JWT verify,
 *                 passport, Firebase verifyIdToken, signature checks, secret-header checks),
 *                 or a helper we resolved whose body performs one, or whose body reads a
 *                 credential (cookie / Authorization / session) and rejects on failure.
 *  - weak:        Supabase `auth.getSession()` alone: it decodes the cookie without
 *                 verifying it with the Auth server.
 *  - unverified:  an auth-looking helper we cannot resolve (package import, dynamic).
 *  - notChecking: an auth-looking helper/wrapper we resolved, whose body checks nothing.
 */

export type AccessKind = 'mutation' | 'read' | 'outbound';
/** How data is reached: through RLS (user-scoped Supabase client) or around it. */
export type Privilege = 'privileged' | 'user-scoped' | 'direct';

export interface Sink {
  readonly kind: AccessKind;
  /** e.g. "supabase .delete()", "prisma.user.update", "fs.writeFile", "openai.chat.completions.create" */
  readonly api: string;
  readonly privilege: Privilege;
}

export type AuthStrength = 'strong' | 'weak' | 'unverified' | 'notChecking';

export interface AuthSignal {
  readonly name: string;
  readonly strength: AuthStrength;
}

export interface Analysis {
  sinks: Sink[];
  auth: AuthSignal[];
  rateLimit: string[];
  managedAuth: boolean;
  /** A webhook signature / shared-secret verification was seen. */
  signature: boolean;
  /** Custom credential verification (password hash compare, OTP compare) was seen. */
  verifiesCredentials: boolean;
}

/** Strongest auth signal; undefined when there is none. */
export function bestAuth(a: Analysis): AuthStrength | undefined {
  for (const s of ['strong', 'weak', 'unverified', 'notChecking'] as const) {
    if (a.auth.some((x) => x.strength === s)) return s;
  }
  return undefined;
}

const MUTATING =
  /^(?:insert|update|upsert|delete|remove|create|createMany|updateMany|deleteMany|save|set|add|destroy|bulkCreate|insertMany|insertOne|updateOne|deleteOne|replaceOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|increment|truncate|executeRaw|\$executeRaw|\$executeRawUnsafe|rpc)$/;
const PRISMA_READ =
  /^(?:findMany|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|count|aggregate|groupBy)$/;
const MONGOOSE_READ = /^(?:find|findOne|findById|countDocuments|aggregate|distinct|exists)$/;
const SUPABASE_QUERY = /^(?:select|insert|update|upsert|delete)$/;
const FS_WRITE =
  /^(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rename|renameSync|createWriteStream|copyFile|copyFileSync|truncate|truncateSync|mkdir|mkdirSync)$/;
const FS_MODULES = /^(?:node:)?fs(?:\/promises)?$|^fs-extra$/;
const HTTP_CLIENT =
  /^(?:fetch|axios|got|ky|\$fetch|ofetch|request|superagent)(?:\.(?:get|post|put|patch|delete|request))?$/;
const SECRET_ENV =
  /process\.env\.[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|CREDENTIALS?)\b|import\.meta\.env\.[A-Z0-9_]*(?:SECRET|PRIVATE)/;

/** Recognised auth APIs, matched on the full dotted callee (or its last segment). */
const KNOWN_AUTH_FULL =
  /(?:^|\.)auth\.getUser$|(?:^|\.)auth\.getClaims$|^auth$|(?:^|\.)auth\(\)\.protect$|(?:^|\.)(?:jwt|jsonwebtoken|jose)\.(?:verify|jwtVerify)$|^passport\.authenticate$|\.auth\.api\.getSession$|\.jwtVerify$|^(?:lucia|auth)\.validateSession$/;
const KNOWN_AUTH_LAST =
  /^(?:getServerSession|currentUser|getAuth|getToken|getKindeServerSession|verifyIdToken|verifySessionCookie|jwtVerify|clerkMiddleware|expressjwt|getIronSession|validateSessionToken|requireAuth|withApiAuthRequired|withPageAuthRequired|getAccessToken)$/;
/** Imports from these packages are auth primitives whatever the local name. */
const AUTH_PACKAGES =
  /^(?:jsonwebtoken|jose|next-auth(?:\/.*)?|@auth\/.+|@clerk\/.+|@supabase\/.+|firebase-admin(?:\/.*)?|lucia|better-auth(?:\/.*)?|iron-session|@kinde-oss\/.+|passport(?:-.+)?|@auth0\/.+|express-jwt|@fastify\/jwt)$/;
const WEAK_AUTH_FULL = /(?:^|\.)auth\.getSession$/;
const SIGNATURE =
  /(?:^|\.)(?:constructEvent|constructEventAsync|timingSafeEqual|verifySignature\w*|verifyWebhook\w*|verifyRequestSignature|validateRequest|isValidSignature|checkSignature|verifyKey)$|(?:^|\.)(?:webhooks?|wh|svix\w*)\.verify$/i;
/** Names that suggest authentication; resolved and inspected before being trusted. */
export const AUTH_NAME =
  /^(?:auth|getSession|getUser|get\w*(?:User|Session|Viewer|Principal|Identity)|assert\w*(?:Auth|User|Session|Admin|Login|Signed)\w*|currentUser|validateRequest|validateSession|verify|authenticate\w*|authorize\w*|require(?:User|Admin|Session|Login|Role|Auth|Team|Member|Org)\w*|ensure\w*(?:Auth|User|Session|Admin)\w*|with\w*(?:Auth|User|Session|Admin)\w*|authenticated|isAuthenticated|isLoggedIn|isAdmin|checkAuth\w*|protect\w*|verify\w*(?:Token|Jwt|JWT|Session|User|Auth)\w*|getAuthUser|getCurrentUser\w*|getLoggedInUser\w*)$/;

export const RATE_LIMIT =
  /rate[_-]?limit|ratelimit|limiter|throttle|slowDown|arcjet|checkRateLimit/i;
const RATE_LIMIT_MODULES =
  /^(?:express-rate-limit|express-slow-down|express-brute|@upstash\/ratelimit|rate-limiter-flexible|@fastify\/rate-limit|next-rate-limit|@arcjet\/[\w-]+|@unkey\/ratelimit|@vercel\/firewall|hono-rate-limiter|@nestjs\/throttler|limiter|bottleneck)$/;
/** Managed auth providers that rate-limit credential endpoints themselves. */
const MANAGED_AUTH_CALL =
  /(?:\.auth\.(?:signInWithPassword|signInWithOtp|signUp|resetPasswordForEmail|verifyOtp|signInWithOAuth|exchangeCodeForSession|updateUser)|signInWithEmailAndPassword|createUserWithEmailAndPassword|sendPasswordResetEmail)$/;
const CREDENTIAL_CHECK =
  /^(?:bcrypt|bcryptjs|argon2|scrypt)\.(?:compare|compareSync|verify)$|^(?:compare|verify|timingSafeEqual)$/;

/** A body that reads a credential and has a rejection path is a custom auth check. */
const READS_CREDENTIAL =
  /cookies\(\)|\.cookies\b|headers\.get\(\s*['"`](?:authorization|cookie|x-[\w-]*(?:key|token|secret))['"`]|headers\s*\[\s*['"`](?:authorization|cookie|x-[\w-]*(?:key|token|secret))|headers\.(?:authorization|cookie)\b|getSession|session/i;
const REJECTS =
  /\bthrow\b|status\(\s*40[13]\b|status:\s*40[13]\b|sendStatus\(\s*40[13]\b|redirect\(|return\s+(?:null|undefined|false)\b|return\s*\{\s*error\b|new\s+(?:Next)?Response\([^)]*40[13]/;

export function isStructuralAuthCheck(body: string): boolean {
  return READS_CREDENTIAL.test(body) && REJECTS.test(body);
}

/** Last segment of a callee: `supabase.auth.getUser` → `getUser`. */
function lastName(n: ts.Expression): string {
  const d = dottedName(n);
  if (d) return d.split('.').pop() ?? d;
  if (ts.isPropertyAccessExpression(n)) return n.name.text;
  if (ts.isCallExpression(n)) return lastName(n.expression);
  return '';
}

/** Callee path through intermediate calls: supabase.from('x').select → supabase.from.select */
function chain(n: ts.Expression): string[] {
  if (ts.isIdentifier(n)) return [n.text];
  if (n.kind === ts.SyntaxKind.ThisKeyword) return ['this'];
  if (ts.isPropertyAccessExpression(n)) return [...chain(n.expression), n.name.text];
  if (ts.isCallExpression(n)) return [...chain(n.expression), '()'];
  if (ts.isAwaitExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n))
    return chain(n.expression);
  return [];
}

/** Full callee text through intermediate calls: `auth().protect`, `admin.auth().verifyIdToken`. */
function fullCallee(n: ts.Expression): string {
  return chain(n)
    .join('.')
    .replace(/\.\(\)/g, '()');
}

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

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Identifier/member used as a value (middleware passed to a route), not called or declared. */
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

/** `fastify.decorate('authenticate', fn)` → fn */
function decoratedFunction(sf: ts.SourceFile, name: string): ts.Node | undefined {
  let found: ts.Node | undefined;
  walk(sf, (n) => {
    if (found) return false;
    if (
      ts.isCallExpression(n) &&
      lastName(n.expression) === 'decorate' &&
      n.arguments[0] &&
      stringValue(n.arguments[0]) === name &&
      n.arguments[1]
    ) {
      found = n.arguments[1];
    }
    return undefined;
  });
  return found;
}

/** Variables bound to SDK clients constructed with a server secret: `new OpenAI({ apiKey: process.env.OPENAI_API_KEY })`. */
function secretClients(sf: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  walk(sf, (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      let init: ts.Expression = n.initializer;
      while (ts.isAwaitExpression(init) || ts.isParenthesizedExpression(init))
        init = init.expression;
      if (ts.isNewExpression(init) && init.arguments && init.arguments.length > 0) {
        const args = init.arguments.map((a) => a.getText(sf)).join(' ');
        if (SECRET_ENV.test(args) || findSecrets(args).length > 0) out.add(n.name.text);
      }
    }
    return undefined;
  });
  return out;
}

interface Followed {
  readonly file: string;
  readonly sf: ts.SourceFile;
  readonly node: ts.Node;
}

export class SignalAnalyzer {
  private readonly ctx: RuleContext;
  private readonly authNames: RegExp;
  private readonly rateNames: RegExp;
  private readonly factsCache = new Map<string, Promise<Privilege>>();
  private readonly clientsCache = new Map<string, Set<string>>();

  constructor(ctx: RuleContext) {
    this.ctx = ctx;
    const extraAuth = ctx.settings.endpoints.authFunctions;
    const extraRate = ctx.settings.endpoints.rateLimitFunctions;
    this.authNames =
      extraAuth.length > 0 ? new RegExp(`^(?:${extraAuth.map(escapeRe).join('|')})$`) : /$^/;
    this.rateNames =
      extraRate.length > 0 ? new RegExp(`^(?:${extraRate.map(escapeRe).join('|')})$`) : /$^/;
  }

  isRateLimitName(name: string): boolean {
    return RATE_LIMIT.test(name) || this.rateNames.test(name);
  }

  /** Privilege of Supabase/Firebase access in a file, following one level of imports. */
  private privilegeOf(file: string, sf: ts.SourceFile): Promise<Privilege> {
    let p = this.factsCache.get(file);
    if (!p) {
      p = (async () => {
        const own = privilegeOfText(sf.text);
        if (own === 'privileged') return 'privileged';
        let best: Privilege | undefined = own;
        for (const b of importBindings(sf)) {
          const target = resolveImport(this.ctx, file, b.spec);
          const t = target ? await this.ctx.readText(target) : undefined;
          const pv = t ? privilegeOfText(t.text) : undefined;
          if (pv === 'privileged') return 'privileged';
          if (pv === 'user-scoped') best = 'user-scoped';
        }
        return best ?? 'direct';
      })();
      this.factsCache.set(file, p);
    }
    return p;
  }

  private clientsOf(file: string, sf: ts.SourceFile): Set<string> {
    let c = this.clientsCache.get(file);
    if (!c) {
      c = secretClients(sf);
      this.clientsCache.set(file, c);
    }
    return c;
  }

  /** Resolve a callee/reference to the function that implements it (same file, local import, or Fastify decorate). */
  private async resolve(
    file: string,
    sf: ts.SourceFile,
    bindings: readonly ImportBinding[],
    ref: ts.Expression,
  ): Promise<Followed | undefined> {
    if (ts.isIdentifier(ref)) {
      const local = localFunction(sf, ref.text);
      if (local) return { file, sf, node: local };
      const b = bindings.find((x) => x.local === ref.text);
      if (!b) return undefined;
      const target = resolveImport(this.ctx, file, b.spec);
      const parsed = target ? await this.ctx.parseTs(target) : undefined;
      if (!target || !parsed) return undefined;
      const fn =
        b.imported === 'default'
          ? defaultExportFunction(parsed.sourceFile)
          : localFunction(parsed.sourceFile, b.imported);
      return fn ? { file: target.relPath, sf: parsed.sourceFile, node: fn } : undefined;
    }
    if (ts.isPropertyAccessExpression(ref)) {
      const fn = decoratedFunction(sf, ref.name.text);
      return fn ? { file, sf, node: fn } : undefined;
    }
    return undefined;
  }

  private importedFromAuthPackage(bindings: readonly ImportBinding[], ref: ts.Expression): boolean {
    const root = ts.isIdentifier(ref)
      ? ref.text
      : ts.isPropertyAccessExpression(ref)
        ? (chain(ref)[0] ?? '')
        : '';
    return bindings.some((b) => b.local === root && AUTH_PACKAGES.test(b.spec));
  }

  /**
   * Analyse handler bodies plus middleware nodes. `depth` limits helper following to one
   * level: same-file helpers and local imported functions.
   */
  async analyse(
    file: string,
    sf: ts.SourceFile,
    nodes: readonly ts.Node[],
    depth = 1,
  ): Promise<Analysis> {
    const result: Analysis = {
      sinks: [],
      auth: [],
      rateLimit: [],
      managedAuth: false,
      signature: false,
      verifiesCredentials: false,
    };
    const privilege = await this.privilegeOf(file, sf);
    const clients = this.clientsOf(file, sf);
    const bindings = importBindings(sf);
    const followed: Followed[] = [];
    const candidates: { name: string; ref: ts.Expression }[] = [];
    const calledHelpers: ts.Identifier[] = [];
    const candidatesToFollow: ts.Expression[] = [];

    /** Classify one callee or middleware reference as an auth signal (or a candidate). */
    const classify = (ref: ts.Expression): boolean => {
      const full = fullCallee(ref);
      const last = lastName(ref);
      if (SIGNATURE.test(full)) {
        result.signature = true;
        result.auth.push({ name: full, strength: 'strong' });
        return true;
      }
      if (WEAK_AUTH_FULL.test(full)) {
        result.auth.push({ name: full, strength: 'weak' });
        return true;
      }
      if (
        KNOWN_AUTH_FULL.test(full) ||
        KNOWN_AUTH_LAST.test(last) ||
        this.authNames.test(last) ||
        this.authNames.test(full)
      ) {
        result.auth.push({ name: full, strength: 'strong' });
        return true;
      }
      if (AUTH_NAME.test(last)) {
        if (this.importedFromAuthPackage(bindings, ref)) {
          result.auth.push({ name: full, strength: 'strong' });
        } else {
          candidates.push({ name: full, ref });
        }
        return true;
      }
      return false;
    };

    const rootRefs = nodes.filter(
      (r): r is ts.Expression => ts.isIdentifier(r) || ts.isPropertyAccessExpression(r),
    );
    for (const root of rootRefs) {
      const full = dottedName(root) ?? '';
      if (this.isRateLimitName(full)) result.rateLimit.push(full);
      if (!classify(root) && depth > 0) {
        const def = await this.resolve(file, sf, bindings, root);
        if (def && !nodes.includes(def.node)) followed.push(def);
      }
    }

    for (const root of nodes) {
      walk(root, (n) => {
        if (
          (ts.isIdentifier(n) || ts.isPropertyAccessExpression(n)) &&
          n !== root &&
          isMiddlewareReference(n)
        ) {
          const full = dottedName(n) ?? '';
          if (this.isRateLimitName(full)) result.rateLimit.push(full);
          if (!classify(n) && depth > 0) {
            const local = ts.isIdentifier(n) ? localFunction(sf, n.text) : undefined;
            if (local && !nodes.includes(local)) followed.push({ file, sf, node: local });
            else candidatesToFollow.push(n);
          }
          return ts.isIdentifier(n) ? undefined : false;
        }
        if (ts.isStringLiteral(n) && RATE_LIMIT_MODULES.test(n.text)) result.rateLimit.push(n.text);
        if (ts.isBinaryExpression(n) && isSecretHeaderComparison(n)) {
          result.signature = true;
          result.auth.push({ name: 'secret header comparison', strength: 'strong' });
        }
        if (ts.isTaggedTemplateExpression(n)) {
          // sql`…` (postgres.js, Neon, Vercel Postgres), db.sql`…`, getSql()`…`, prisma.$queryRaw`…`
          const tag = n.tag.getText(sf).replace(/\s+/g, '');
          if (/^(?:\w+\.)?sql$|^\w*[sS]ql\(\)$|\.\$(?:queryRaw|executeRaw)(?:Unsafe)?$/.test(tag)) {
            result.sinks.push({
              kind: sqlKind(n.template.getText(sf)),
              api: `${tag}\`…\``,
              privilege: 'direct',
            });
          }
          return undefined;
        }
        if (!ts.isCallExpression(n)) return undefined;

        const full = fullCallee(n.expression);
        const last = lastName(n.expression);
        const parts = chain(n.expression).filter((p) => p !== '()');
        if (this.isRateLimitName(full)) result.rateLimit.push(full);
        if (MANAGED_AUTH_CALL.test(full)) result.managedAuth = true;
        if (CREDENTIAL_CHECK.test(full)) result.verifiesCredentials = true;
        const isAuth = classify(n.expression);

        const sink = sinkOf(parts, last, n);
        if (sink)
          result.sinks.push({
            kind: sink.kind,
            api: sink.api,
            privilege: sink.supabaseOrFirebase ? privilege : 'direct',
          });
        const extra = this.extraSink(sf, bindings, clients, parts, full, last, n);
        if (extra) result.sinks.push(extra);

        // Follow one level into helpers that are not themselves auth candidates.
        if (!isAuth && depth > 0 && ts.isIdentifier(n.expression)) calledHelpers.push(n.expression);
        return undefined;
      });
    }

    // Same-file and imported helpers called from the handler (non-auth names): sinks and auth propagate.
    for (const ref of [...calledHelpers, ...candidatesToFollow]) {
      const def = await this.resolve(file, sf, bindings, ref);
      if (def && !nodes.includes(def.node)) followed.push(def);
    }
    for (const f of followed)
      this.merge(result, await this.analyse(f.file, f.sf, [f.node], depth - 1));

    // Auth-named helpers: trust them only after looking inside.
    for (const c of candidates) {
      const def = depth > 0 ? await this.resolve(file, sf, bindings, c.ref) : undefined;
      if (!def) {
        result.auth.push({ name: c.name, strength: 'unverified' });
        continue;
      }
      const sub = await this.analyse(def.file, def.sf, [def.node], depth - 1);
      const inner = bestAuth(sub);
      const strength: AuthStrength =
        inner === 'strong' || isStructuralAuthCheck(def.node.getText(def.sf))
          ? 'strong'
          : inner === 'weak'
            ? 'weak'
            : inner === 'unverified'
              ? 'unverified'
              : 'notChecking';
      result.auth.push({ name: c.name, strength });
      result.sinks.push(...sub.sinks);
      result.rateLimit.push(...sub.rateLimit);
      if (sub.signature) result.signature = true;
    }
    return result;
  }

  private merge(into: Analysis, sub: Analysis): void {
    into.sinks.push(...sub.sinks);
    into.auth.push(...sub.auth);
    into.rateLimit.push(...sub.rateLimit);
    if (sub.managedAuth) into.managedAuth = true;
    if (sub.signature) into.signature = true;
    if (sub.verifiesCredentials) into.verifiesCredentials = true;
  }

  /** File writes and outbound calls made with server secrets. */
  private extraSink(
    sf: ts.SourceFile,
    bindings: readonly ImportBinding[],
    clients: ReadonlySet<string>,
    parts: readonly string[],
    full: string,
    last: string,
    call: ts.CallExpression,
  ): Sink | undefined {
    const root = parts[0] ?? '';
    if (FS_WRITE.test(last)) {
      const fsRoot = /^(?:fs|fsp|fsPromises|fse)$/.test(root) || parts.includes('promises');
      const fsImport = bindings.some(
        (b) => (b.local === root || b.local === last) && FS_MODULES.test(b.spec),
      );
      if (fsRoot || fsImport) return { kind: 'mutation', api: `fs.${last}()`, privilege: 'direct' };
    }
    if (HTTP_CLIENT.test(full)) {
      const args = call.arguments.map((a) => a.getText(sf)).join(' ');
      if (SECRET_ENV.test(args) || findSecrets(args).length > 0)
        return { kind: 'outbound', api: `${full}() with a server secret`, privilege: 'privileged' };
    }
    if (clients.has(root) && parts.length >= 2)
      return { kind: 'outbound', api: `${parts.join('.')}()`, privilege: 'privileged' };
    return undefined;
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

const SQL_STATEMENT = /^\s*(?:with|select|insert|update|delete|replace|upsert|merge)\b/i;

/** SQL text of a string or template literal argument, if it looks like a statement. */
function sqlTextOf(n: ts.Node): string | undefined {
  const text =
    stringValue(n) ?? (ts.isTemplateExpression(n) ? n.getText().slice(1, -1) : undefined);
  return text !== undefined && SQL_STATEMENT.test(text) ? text : undefined;
}

function sqlKind(text: string): 'mutation' | 'read' {
  return /\b(?:insert|update|delete|replace|upsert|merge|drop|alter|truncate)\b/i.test(text)
    ? 'mutation'
    : 'read';
}

interface RawSink {
  readonly kind: 'mutation' | 'read';
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
