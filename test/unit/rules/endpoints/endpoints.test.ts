import { describe, expect, it } from 'vitest';
import { appRouterPath, findEndpoints } from '../../../../src/analysis/routes.ts';
import { resolveSettings } from '../../../../src/core/config/settings.ts';
import { ProjectContext } from '../../../../src/core/engine/context.ts';
import { scan } from '../../../../src/core/engine/engine.ts';
import type { Rule } from '../../../../src/core/engine/rule.ts';
import { discoverFiles } from '../../../../src/core/discovery/walker.ts';
import { authRouteNoRateLimitRule } from '../../../../src/rules/endpoints/auth-route-no-rate-limit.rule.ts';
import { corsWildcardCredentialsRule } from '../../../../src/rules/endpoints/cors-wildcard-credentials.rule.ts';
import { matcherToRegExp } from '../../../../src/rules/endpoints/next-middleware.ts';
import { webhookWithoutSignatureRule } from '../../../../src/rules/endpoints/webhook-without-signature.rule.ts';
import {
  unauthenticatedDataAccessRule,
  verdictFor,
} from '../../../../src/rules/endpoints/unauthenticated-data-access.rule.ts';
import { makeProject } from '../../../helpers/project.ts';

const NEXT = {
  'package.json': '{"dependencies":{"next":"15"}}',
  'next.config.mjs': 'export default {};',
};

async function run(
  rule: Rule,
  files: Record<string, string>,
  config?: Parameters<typeof resolveSettings>[0],
) {
  const root = await makeProject(files);
  const r = await scan({ root, settings: resolveSettings(config), rules: [rule] });
  expect(r.complete).toBe(true);
  return r.findings;
}

const summary = (fs: Awaited<ReturnType<typeof run>>) =>
  fs.map((f) =>
    `${f.messageId} ${String(f.params['endpoint'] ?? '')} ${f.location.file}:${f.location.line}`.trim(),
  );

describe('endpoint extraction', () => {
  async function endpoints(files: Record<string, string>) {
    const root = await makeProject(files);
    const { files: recs } = await discoverFiles({ root });
    const ctx = new ProjectContext(root, resolveSettings(undefined), recs);
    return (await findEndpoints(ctx))
      .map(
        (e) =>
          `${e.kind} ${e.method} ${e.path} mw=${e.middleware.length} inh=${e.inherited.length}`,
      )
      .sort();
  }

  it('derives App Router paths, ignoring route groups and parallel slots', () => {
    expect(appRouterPath('src/app/(admin)/api/users/[id]/route.ts')).toBe('/api/users/[id]');
    expect(appRouterPath('app/@modal/api/x/route.js')).toBe('/api/x');
    expect(appRouterPath('app/route.ts')).toBe('/');
  });

  it('finds every Next.js handler form, Pages API, Vercel functions and server actions', async () => {
    expect(
      await endpoints({
        ...NEXT,
        'app/api/a/route.ts':
          'export async function GET() {}\nexport const POST = withAuth(async () => {});\nconst h = () => {};\nexport { h as PUT };',
        'pages/api/b.ts': 'export default function handler(req, res) {}',
        'app/actions.ts':
          "'use server';\nexport async function save() {}\nexport const remove = async () => {};\nasync function hidden() {}",
        'app/page.tsx':
          "export default function P() { async function inline() { 'use server'; } return null; }",
      }),
    ).toEqual([
      'next-pages-api ANY /api/b mw=0 inh=0',
      'next-route GET /api/a mw=0 inh=0',
      'next-route POST /api/a mw=1 inh=0',
      'next-route PUT /api/a mw=0 inh=0',
      'server-action ACTION inline mw=0 inh=0',
      'server-action ACTION remove mw=0 inh=0',
      'server-action ACTION save mw=0 inh=0',
    ]);
    expect(await endpoints({ 'api/x.ts': 'export default async function handler() {}' })).toEqual([
      'vercel-function ANY /api/x mw=0 inh=0',
    ]);
  });

  it('finds Express routes, chained route(), Router, and ordered app.use middleware', async () => {
    expect(
      await endpoints({
        'server.js': [
          "const express = require('express');",
          'const app = express();',
          "app.get('/public', h);",
          'app.use(auth);',
          "app.post('/a', mw1, mw2, h);",
          "app.use('/admin', adminOnly);",
          "app.delete('/admin/x', h);",
          "app.delete('/other', h);",
          'const router = express.Router();',
          "router.route('/r').get(h).post(h);",
          "app.get('port');",
        ].join('\n'),
      }),
    ).toEqual([
      'express DELETE /admin/x mw=0 inh=2',
      'express DELETE /other mw=0 inh=1',
      'express GET /public mw=0 inh=0',
      'express GET /r mw=0 inh=0',
      'express POST /a mw=2 inh=1',
      'express POST /r mw=0 inh=0',
    ]);
  });

  it('finds Fastify shorthand routes with options, route({...}) and hooks', async () => {
    expect(
      await endpoints({
        'f.js': [
          "const fastify = require('fastify')();",
          "fastify.get('/a', { preHandler: [fastify.authenticate] }, async () => 1);",
          "fastify.route({ method: ['POST', 'PUT'], url: '/b', handler: async () => 1 });",
          "fastify.addHook('onRequest', check);",
        ].join('\n'),
      }),
    ).toEqual([
      'fastify GET /a mw=1 inh=1',
      'fastify POST /b mw=0 inh=1',
      'fastify PUT /b mw=0 inh=1',
    ]);
  });
});

describe('endpoints/unauthenticated-data-access', () => {
  const admin = {
    'src/lib/admin.ts':
      'export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
  };
  const userClient = {
    'src/lib/server.ts':
      "import { createServerClient } from '@supabase/ssr';\nexport async function createClient() { return createServerClient(u, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {}); }",
  };

  it('rates sinks by kind and privilege', () => {
    expect(
      verdictFor([
        { kind: 'read', api: 'x', privilege: 'direct' },
        { kind: 'mutation', api: 'y', privilege: 'privileged' },
      ])?.verdict.messageId,
    ).toBe('privilegedMutation');
    expect(verdictFor([{ kind: 'read', api: 'x', privilege: 'user-scoped' }])).toBeUndefined();
    expect(
      verdictFor([{ kind: 'mutation', api: 'x', privilege: 'user-scoped' }])?.verdict,
    ).toMatchObject({ severity: 'low', confidence: 'low' });
  });

  it.each([
    [
      'supabase',
      "import { admin } from '@/lib/admin';\nexport async function POST() { await admin.from('t').insert({}); }",
      'privilegedMutation',
    ],
    [
      'prisma',
      'export async function DELETE() { await prisma.user.delete({ where: { id: 1 } }); }',
      'mutation',
    ],
    [
      'prisma raw',
      'export async function POST() { await prisma.$executeRaw`DELETE FROM t`; }',
      'mutation',
    ],
    [
      'drizzle',
      'export async function PATCH() { await db.update(users).set({ a: 1 }); }',
      'mutation',
    ],
    [
      'drizzle query API',
      'export async function GET() { return Response.json(await db.query.users.findMany()); }',
      'read',
    ],
    [
      'mongoose',
      'export async function GET() { return Response.json(await User.find()); }',
      'read',
    ],
    ['pg', "export async function POST() { await pool.query('UPDATE t SET a = 1'); }", 'mutation'],
    [
      'sql tag',
      'export async function POST() { await sql`insert into t values (1)`; }',
      'mutation',
    ],
    [
      'firestore admin',
      "import admin from 'firebase-admin';\nexport async function POST() { await admin.firestore().collection('u').doc('1').set({}); }",
      'privilegedMutation',
    ],
    [
      'user-scoped supabase',
      "import { createClient } from '@/lib/server';\nexport async function POST() { const s = await createClient(); await s.from('t').delete(); }",
      'rlsGuardedMutation',
    ],
  ])('reports %s data access without auth', async (_l, src, id) => {
    const f = await run(unauthenticatedDataAccessRule, {
      ...NEXT,
      ...admin,
      ...userClient,
      'src/app/api/x/route.ts': src,
    });
    expect(f.map((x) => x.messageId)).toEqual([id]);
  });

  it.each([
    [
      'getUser check',
      'export async function POST() { const { data } = await supabase.auth.getUser(); if (!data.user) return; await prisma.t.create({ data: {} }); }',
    ],
    [
      'NextAuth auth()',
      'export async function POST() { const s = await auth(); if (!s) return; await prisma.t.create({ data: {} }); }',
    ],
    [
      'getServerSession',
      'export async function DELETE() { await getServerSession(opts); await db.delete(t); }',
    ],
    [
      'Clerk currentUser',
      'export async function POST() { const u = await currentUser(); await db.insert(t).values({}); }',
    ],
    [
      'webhook signature',
      'export async function POST(r) { stripe.webhooks.constructEvent(b, s, k); await db.insert(t).values({}); }',
    ],
    [
      'cron secret',
      "export async function GET(r) { if (r.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return; await db.delete(t); }",
    ],
    [
      'API key header',
      "export async function POST(r) { if (r.headers.get('x-api-key') !== process.env.INTERNAL_API_KEY) return; await db.delete(t); }",
    ],
    [
      'same-file helper',
      'async function me() { return (await supabase.auth.getUser()).data.user; }\nexport async function POST() { await me(); await db.delete(t); }',
    ],
    [
      'configured auth function',
      'export async function POST() { await mustBeMember(); await db.delete(t); }',
    ],
    ['no data access', 'export async function POST() { return Response.json({ ok: true }); }'],
    [
      'health endpoint',
      'export async function GET() { return Response.json(await db.select().from(t)); }',
    ],
  ])('does not report: %s', async (label, src) => {
    const route =
      label === 'health endpoint' ? 'src/app/api/health/route.ts' : 'src/app/api/x/route.ts';
    const config =
      label === 'configured auth function'
        ? { version: 1 as const, endpoints: { authFunctions: ['mustBeMember'] } }
        : undefined;
    expect(await run(unauthenticatedDataAccessRule, { ...NEXT, [route]: src }, config)).toEqual([]);
  });

  it('follows auth into helpers imported from local modules', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      ...NEXT,
      'src/lib/guard.ts':
        'export async function whoAmI() { const { data } = await supabase.auth.getUser(); return data.user; }',
      'src/app/api/x/route.ts':
        "import { whoAmI } from '@/lib/guard';\nexport async function POST() { await whoAmI(); await db.delete(t); }",
    });
    expect(f).toEqual([]);
  });

  it('honours Next.js middleware only when it blocks and its matcher covers the route', async () => {
    const route = {
      'src/app/api/admin/x/route.ts': 'export async function DELETE() { await db.delete(t); }',
      'src/app/api/open/route.ts': 'export async function DELETE() { await db.delete(t); }',
    };
    const blocking =
      "export async function middleware(r) { const { data } = await supabase.auth.getUser(); if (!data.user) return NextResponse.redirect(new URL('/login', r.url)); }\nexport const config = { matcher: ['/api/admin/:path*'] };";
    const refreshOnly =
      'export async function middleware(r) { await supabase.auth.getUser(); return NextResponse.next(); }';
    expect(
      summary(
        await run(unauthenticatedDataAccessRule, {
          ...NEXT,
          ...route,
          'src/middleware.ts': blocking,
        }),
      ),
    ).toEqual(['mutation DELETE /api/open src/app/api/open/route.ts:1']);
    expect(
      await run(unauthenticatedDataAccessRule, {
        ...NEXT,
        ...route,
        'src/middleware.ts': refreshOnly,
      }),
    ).toHaveLength(2);
  });

  it('handles Express route-level, app-level and router-level auth', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      'server.js': [
        "const express = require('express');",
        'const app = express();',
        "app.get('/open', async (req, res) => res.json(await User.find()));",
        "app.delete('/guarded', requireAuth, async (req, res) => { await User.deleteOne({}); });",
        'function requireAuth(req, res, next) { if (!req.headers.authorization) return res.sendStatus(401); next(); }',
        "app.post('/passport', passport.authenticate('jwt'), async () => { await User.create({}); });",
        'app.use(isAuthenticated);',
        "app.delete('/later', async () => { await User.deleteMany({}); });",
      ].join('\n'),
    });
    // requireAuth is defined in the file (checks a token); passport.authenticate is a known API;
    // isAuthenticated is not resolvable, so the later route is unverified (low), never "safe".
    expect(f.map((x) => [x.messageId, x.params['endpoint'], x.confidence])).toEqual([
      // sorted by severity: the unverified mutation (high) before the open read (medium)
      ['unverifiedAuth', 'DELETE /later', 'low'],
      ['read', 'GET /open', 'low'],
    ]);
  });

  it('skips credential endpoints (handled by the rate-limit rule)', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      ...NEXT,
      'src/app/api/login/route.ts':
        'export async function POST() { await db.select().from(users); }',
    });
    expect(f).toEqual([]);
  });
});

describe('endpoints/cors-wildcard-credentials', () => {
  it.each([
    ['app.use(cors({ origin: true, credentials: true }));', 'reflectedOrigin'],
    ['app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));', 'reflectedOrigin'],
    ["app.use(cors({ origin: '*', credentials: true }));", 'wildcardWithCredentials'],
    ['app.use(cors({ credentials: true }));', 'wildcardWithCredentials'],
    [
      "fastify.register(require('@fastify/cors'), { origin: true, credentials: 'true' });",
      'reflectedOrigin',
    ],
    [
      "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
      'reflectedOrigin',
    ],
    [
      "return new Response(b, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' } });",
      'wildcardWithCredentials',
    ],
  ])('reports %s', async (src, id) => {
    const f = await run(corsWildcardCredentialsRule, { 'server.js': src });
    expect(f.map((x) => x.messageId)).toEqual([id]);
  });

  it.each([
    ['app.use(cors());'],
    ["app.use(cors({ origin: '*' }));"],
    ["app.use(cors({ origin: ['https://a.example'], credentials: true }));"],
    ["app.use(cors({ origin: 'https://a.example', credentials: true }));"],
    ['app.use(cors({ origin: /\\.example\\.com$/, credentials: true }));'],
    [
      'app.use(cors({ origin: (o, cb) => cb(null, allowedOrigins.includes(o)), credentials: true }));',
    ],
    [
      "const allowed = ['https://a.example'];\nif (allowed.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
    ],
    ["res.setHeader('Access-Control-Allow-Origin', '*');"],
    [
      "const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization' };",
    ],
  ])('does not report %s', async (src) => {
    expect(await run(corsWildcardCredentialsRule, { 'server.js': src })).toEqual([]);
  });
});

describe('endpoints/auth-route-no-rate-limit', () => {
  it('reports custom credential endpoints without a limiter', async () => {
    const f = await run(authRouteNoRateLimitRule, {
      ...NEXT,
      'src/app/api/auth/login/route.ts': 'export async function POST() {}',
      'src/app/actions.ts':
        "'use server';\nexport async function resetPassword() {}\nexport async function saveDraft() {}",
      'server.js':
        "const app = require('express')();\napp.post('/signup', async () => {});\napp.get('/login', (req, res) => res.render('login'));",
    });
    expect(summary(f)).toEqual([
      'noRateLimit POST /signup server.js:2',
      'noRateLimit server action resetPassword() src/app/actions.ts:2',
      'noRateLimit POST /api/auth/login src/app/api/auth/login/route.ts:1',
    ]);
  });

  it.each([
    [
      'express-rate-limit by any name',
      "const rateLimit = require('express-rate-limit');\nconst guard = rateLimit({ limit: 5 });\nconst app = require('express')();\napp.post('/login', guard, async () => {});",
    ],
    [
      'app-level limiter',
      "const app = require('express')();\napp.use(limiter);\napp.post('/login', async () => {});",
    ],
    [
      'fastify plugin',
      "const fastify = require('fastify')();\nfastify.register(require('@fastify/rate-limit'), { max: 5 });\nfastify.post('/login', async () => {});",
    ],
    [
      'upstash in handler',
      "const app = require('express')();\napp.post('/login', async (req) => { await ratelimit.limit(req.ip); });",
    ],
    [
      'delegates to Supabase Auth',
      "const app = require('express')();\napp.post('/login', async (req) => { await supabase.auth.signInWithPassword(req.body); });",
    ],
    [
      'configured limiter',
      "const app = require('express')();\napp.post('/login', bouncer, async () => {});",
    ],
    [
      'NextAuth catch-all',
      'export { handler as GET, handler as POST };\nconst handler = NextAuth(opts);',
    ],
  ])('does not report: %s', async (label, src) => {
    const files =
      label === 'NextAuth catch-all'
        ? { ...NEXT, 'app/api/auth/[...nextauth]/route.ts': src }
        : { 'server.js': src };
    const config =
      label === 'configured limiter'
        ? { version: 1 as const, endpoints: { rateLimitFunctions: ['bouncer'] } }
        : undefined;
    expect(await run(authRouteNoRateLimitRule, files, config)).toEqual([]);
  });
});

describe('matcherToRegExp', () => {
  it.each([
    ['/api/:path*', '/api/a/b', true],
    ['/api/:path*', '/api', true],
    ['/dashboard/:id', '/dashboard/1', true],
    ['/dashboard/:id', '/dashboard/1/2', false],
    ['/((?!_next/static|_next/image|favicon.ico).*)', '/api/x', true],
    ['/((?!api|_next).*)', '/api/x', false],
  ])('%s matches %s → %s', (src, path, ok) => {
    expect(matcherToRegExp(src)?.test(path)).toBe(ok);
  });
});

describe('prepared statements, SQL tags and project-specific auth helpers', () => {
  const route = (src: string) => ({ ...NEXT, 'src/app/api/x/route.ts': src });

  it.each([
    [
      'D1 prepared write',
      "export async function POST() { await getD1().prepare('INSERT INTO t (a) VALUES (?1)').bind(1).run(); }",
      'mutation',
    ],
    [
      'D1 prepared read',
      'export async function GET() { return Response.json(await env.DB.prepare(`SELECT * FROM t WHERE a = ?1`).bind(1).all()); }',
      'read',
    ],
    [
      'better-sqlite3 exec',
      "export async function POST() { db.exec('DELETE FROM t'); }",
      'mutation',
    ],
    [
      'sql tag from a factory',
      'export async function POST() { await getSql()`delete from t`; }',
      'mutation',
    ],
  ])('reports %s', async (_l, src, id) => {
    expect((await run(unauthenticatedDataAccessRule, route(src))).map((f) => f.messageId)).toEqual([
      id,
    ]);
  });

  it.each([
    [
      'get…User helper (resolved, checks the cookie)',
      "async function getMemberUser() { const sid = (await cookies()).get('sid'); if (!sid) return null; return lookup(sid); }\nexport async function POST() { if (!(await getMemberUser())) return; await db.delete(t); }",
    ],
    [
      'assert…Auth helper (resolved, calls getUser)',
      "async function assertAuthenticated() { const { data } = await supabase.auth.getUser(); if (!data.user) throw new Error('401'); }\nexport async function POST() { await assertAuthenticated(); await db.delete(t); }",
    ],
    [
      'prepare() of a non-SQL string',
      "export async function POST() { await tpl.prepare('welcome-email'); }",
    ],
  ])('does not report: %s', async (_l, src) => {
    expect(await run(unauthenticatedDataAccessRule, route(src))).toEqual([]);
  });
});

describe('regressions found on a real project (generic patterns)', () => {
  it('treats authenticate*/authorize* helpers as auth once their body is seen to check', async () => {
    const src =
      "async function authenticateAdminRequest(r) { const token = r.headers.get('authorization'); if (!token) return { error: 'unauthorized' }; return lookup(token); }\nexport async function DELETE(r) { const a = await authenticateAdminRequest(r); if ('error' in a) return; await db.delete(t); }";
    expect(
      await run(unauthenticatedDataAccessRule, { ...NEXT, 'src/app/api/x/route.ts': src }),
    ).toEqual([]);
    const src2 =
      "import { authorizeOrgMember } from '@acme/auth';\nexport async function POST(r) { await authorizeOrgMember(r); await db.delete(t); }";
    const unresolved = await run(unauthenticatedDataAccessRule, {
      ...NEXT,
      'src/app/api/y/route.ts': src2,
    });
    expect(unresolved.map((f) => [f.messageId, f.confidence])).toEqual([['unverifiedAuth', 'low']]);
  });

  it('does not require auth before logout / sign-out', async () => {
    const src = 'export async function POST() { await db.delete(sessions); }';
    expect(
      await run(unauthenticatedDataAccessRule, {
        ...NEXT,
        'src/app/api/admin/session/logout/route.ts': src,
      }),
    ).toEqual([]);
    expect(
      await run(unauthenticatedDataAccessRule, {
        ...NEXT,
        'src/app/actions.ts':
          "'use server';\nexport async function signOut() { await db.delete(sessions); }",
      }),
    ).toEqual([]);
  });
});

describe('auth certainty (never silently pass, never overclaim)', () => {
  const r = (files: Record<string, string>) =>
    run(unauthenticatedDataAccessRule, { ...NEXT, ...files });

  it('reports getSession()-only as weak auth, one severity lower', async () => {
    const f = await r({
      'src/app/api/x/route.ts':
        'export async function DELETE() { const { data } = await supabase.auth.getSession(); if (!data.session) return; await db.delete(t); }',
    });
    expect(f.map((x) => [x.messageId, x.severity, x.confidence])).toEqual([
      ['weakAuth', 'medium', 'medium'],
    ]);
  });

  it('getUser() alongside getSession() is strong', async () => {
    const f = await r({
      'src/app/api/x/route.ts':
        'export async function DELETE() { await supabase.auth.getSession(); await supabase.auth.getUser(); await db.delete(t); }',
    });
    expect(f).toEqual([]);
  });

  it('follows a wrapper one level and reports it when it does not check', async () => {
    const noCheck = {
      'src/lib/w.ts':
        'export function withAuth(h) { return async (req) => { console.log(req.url); return h(req); }; }',
    };
    const checks = {
      'src/lib/w.ts':
        "export function withAuth(h) { return async (req) => { const s = await auth(); if (!s) return new Response('no', { status: 401 }); return h(req); }; }",
    };
    const route = {
      'src/app/api/x/route.ts':
        "import { withAuth } from '@/lib/w';\nexport const POST = withAuth(async () => { await db.delete(t); });",
    };
    expect((await r({ ...noCheck, ...route })).map((x) => [x.messageId, x.confidence])).toEqual([
      ['wrapperDoesNotCheck', 'medium'],
    ]);
    expect(await r({ ...checks, ...route })).toEqual([]);
  });

  it('reports an unresolvable auth-named wrapper as unverified, low confidence', async () => {
    const f = await r({
      'src/app/api/x/route.ts':
        "import { withAuth } from '@acme/auth';\nexport const POST = withAuth(async () => { await db.delete(t); });",
    });
    expect(f.map((x) => [x.messageId, x.confidence])).toEqual([['unverifiedAuth', 'low']]);
  });

  it('treats auth imported from known auth packages as strong whatever the local name', async () => {
    const f = await r({
      'src/app/api/x/route.ts':
        "import { verify as checkJwt } from 'jsonwebtoken';\nimport { requireMember } from 'next-auth/custom';\nexport async function POST() { await requireMember(); await db.delete(t); }",
    });
    expect(f).toEqual([]);
  });

  it('never assumes coverage from a matcher it cannot parse', async () => {
    const mw =
      "export async function middleware(r) { const s = await auth(); if (!s) return NextResponse.redirect(new URL('/login', r.url)); }\nexport const config = { matcher: ['/api/(unclosed'] };";
    const f = await r({
      'src/middleware.ts': mw,
      'src/app/api/x/route.ts': 'export async function POST() { await db.delete(t); }',
    });
    expect(f.map((x) => [x.messageId, x.confidence])).toEqual([['unverifiedAuth', 'low']]);
  });

  it('respects Express ordering: auth registered after a route does not protect it', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      'server.js': [
        "const app = require('express')();",
        'function requireAuth(req, res, next) { if (!req.headers.authorization) return res.sendStatus(401); next(); }',
        "app.post('/before', async () => { await User.create({}); });",
        'app.use(requireAuth);',
        "app.post('/after', async () => { await User.create({}); });",
      ].join('\n'),
    });
    expect(f.map((x) => x.params['endpoint'])).toEqual(['POST /before']);
  });

  it('scopes Fastify hooks to their plugin (encapsulation)', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      'f.js': [
        "const fastify = require('fastify')();",
        "fastify.decorate('authenticate', async (request) => request.jwtVerify());",
        'fastify.register(async function plugin(fastify) {',
        "  fastify.addHook('onRequest', fastify.authenticate);",
        "  fastify.delete('/inside', async () => db.delete(t));",
        '});',
        "fastify.delete('/outside', async () => db.delete(t));",
      ].join('\n'),
    });
    expect(f.map((x) => x.params['endpoint'])).toEqual(['DELETE /outside']);
  });

  it('reports file writes and outbound calls with server secrets as sensitive', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      'server.js': [
        "const fs = require('fs');",
        "const app = require('express')();",
        'const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });',
        "app.post('/upload', async (req) => { await fs.promises.writeFile('x', req.body); });",
        "app.post('/ask', async (req) => openai.chat.completions.create({}));",
        "app.post('/hook', async (req) => fetch('https://api.x', { headers: { Authorization: `Bearer ${process.env.X_API_KEY}` } }));",
        "app.get('/static', (req, res) => res.json({ ok: true }));",
      ].join('\n'),
    });
    expect(f.map((x) => [x.params['endpoint'], x.messageId])).toEqual([
      ['POST /upload', 'mutation'],
      ['POST /ask', 'secretSpend'],
      ['POST /hook', 'secretSpend'],
    ]);
  });
});

describe('endpoints/webhook-without-signature', () => {
  const r = (src: string) =>
    run(webhookWithoutSignatureRule, { ...NEXT, 'src/app/api/webhooks/x/route.ts': src });

  it('reports unsigned webhooks, higher when they write', async () => {
    expect(
      (
        await r(
          'export async function POST(q) { const e = await q.json(); await db.update(orders).set({ paid: true }); }',
        )
      ).map((f) => [f.messageId, f.severity, f.confidence]),
    ).toEqual([['unsignedWrites', 'high', 'medium']]);
    expect(
      (await r('export async function POST(q) { console.log(await q.json()); }')).map(
        (f) => f.messageId,
      ),
    ).toEqual(['unsigned']);
  });

  it.each([
    [
      'Stripe',
      'export async function POST(q) { stripe.webhooks.constructEvent(b, s, k); await db.delete(t); }',
    ],
    [
      'svix',
      'export async function POST(q) { new Webhook(k); wh.verify(b, h); await db.delete(t); }',
    ],
    [
      'HMAC + timingSafeEqual',
      'export async function POST(q) { const d = createHmac("sha256", k).update(b).digest(); if (!timingSafeEqual(d, sig)) return; await db.delete(t); }',
    ],
    [
      'shared secret header',
      "export async function POST(q) { if (q.headers.get('x-webhook-secret') !== process.env.WEBHOOK_SECRET) return; await db.delete(t); }",
    ],
  ])('does not report a webhook verified with %s', async (_l, src) => {
    expect(await r(src)).toEqual([]);
  });

  it('is not double-reported by unauthenticated-data-access', async () => {
    const f = await run(unauthenticatedDataAccessRule, {
      ...NEXT,
      'src/app/api/webhooks/x/route.ts': 'export async function POST() { await db.delete(t); }',
    });
    expect(f).toEqual([]);
  });
});

describe('cors: permissive origin on cookie-authenticated code', () => {
  it('reports low/low only when the code uses cookies', async () => {
    const cookie = await run(corsWildcardCredentialsRule, {
      'a.ts': "const s = cookies().get('sid');\nres.setHeader('Access-Control-Allow-Origin', '*');",
    });
    expect(cookie.map((f) => [f.messageId, f.severity, f.confidence])).toEqual([
      ['permissiveOnCookieRoute', 'low', 'low'],
    ]);
    const bearer = await run(corsWildcardCredentialsRule, {
      'b.ts':
        "const t = req.headers.get('Authorization');\nconst corsHeaders = { 'Access-Control-Allow-Origin': '*' };",
    });
    expect(bearer).toEqual([]);
  });
});
