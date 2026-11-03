# ADR-0012: Detecting unauthenticated endpoints syntactically

- Status: Accepted
- Date: 2026-11-03

## Context

"This endpoint touches data and nobody checked who is calling" is the single most common
backend flaw in AI-generated apps. Proving authentication precisely needs data-flow and type
analysis across the whole program. We have a per-file syntax tree, one level of import
resolution and no type checker (ADR-0001, ADR-0010).

## Decision

**Endpoints** are extracted syntactically (`src/analysis/routes.ts`): Next.js App Router
handlers (all export forms, including `withAuth(handler)` wrappers), Pages Router API routes,
Vercel `api/` functions, server actions (module-level and inline `'use server'`),
Express/Router (`app.METHOD`, `route().METHOD` chains, ordered `app.use`, prefix-scoped
`use`), and Fastify (shorthand routes with options, `route({...})`, `addHook`, which applies
regardless of order).

**An endpoint is reported** when, with no auth signal, its handler (plus same-file helpers and
local imported functions, one level) reaches a **data-access sink**: Supabase
query/rpc/storage, Firestore, Prisma (including raw queries), Drizzle, Mongoose-style models,
`pg`/`mysql` `.query()`, or `sql` tagged templates.

**Auth signals** are calls or middleware matching a curated list (`getUser`, `auth()`,
`getServerSession`, `currentUser`, `verifyIdToken`, `jwt.verify`/`jwtVerify`,
`passport.authenticate`, `require*`/`ensure*`/`with*Auth*` helpers, …), webhook signature
verification (`constructEvent`, `verify*Signature`), comparisons of a request header with a
secret env var (cron secrets, internal API keys), and user-configured `endpoints.authFunctions`.
Next.js `middleware.ts`/`proxy.ts` counts only when it both checks auth **and** blocks
(redirect / 401 / 403), and its `matcher` (path-to-regexp semantics) covers the route. The
Supabase SSR template that only refreshes the session cookie is deliberately _not_
protection.

**Severity follows reach**, not just presence:

| Sink                                                                           | Severity / confidence                               |
| ------------------------------------------------------------------------------ | --------------------------------------------------- |
| Mutation with a privileged client (service role, `sb_secret_`, Firebase Admin) | critical / high                                     |
| Mutation, direct DB access (ORM, SQL)                                          | high / high                                         |
| Read with a privileged client (bypasses RLS)                                   | high / medium                                       |
| Read, direct DB access                                                         | medium / **low** (data may be intentionally public) |
| Mutation through a user-scoped Supabase client                                 | low / low (RLS is the only guard)                   |
| Read through a user-scoped Supabase client                                     | not reported (RLS decides, by design)               |

Credential endpoints (login, signup, reset, OTP) are excluded from this rule; they are public
by necessity and are covered by `endpoints/auth-route-no-rate-limit`. That rule skips
endpoints that delegate to Supabase Auth or Firebase Auth, which rate-limit themselves, and
library catch-all handlers (`[...nextauth]`).

## Consequences

- **Presence, not dominance.** An auth call anywhere in the handler counts, even when its
  result is ignored or checked after the write. Proving that the check guards the sink would
  need control-flow analysis. Documented in the threat model.
- **Authorization is out of scope.** "Logged in" is treated as sufficient. IDOR (user A
  editing user B's record) is not detected by this rule.
- Routers mounted from other files (`app.use('/admin', requireAuth, adminRouter)`) do not
  propagate auth into the router's file. The router's own routes are judged on their own
  middleware. This can cause false positives, which users resolve with `router.use(auth)`
  (recommended anyway) or a suppression.
- Names matter. A project-specific guard called `gate()` is invisible until listed in
  `endpoints.authFunctions`.
