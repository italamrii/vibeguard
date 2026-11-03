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

## Amendment (2026-11-03): three-state auth, webhooks, more sinks

Prompted by the principle that false positives are this family's biggest risk, and that
undetermined auth must never silently pass or be overclaimed:

- **Names are no longer trusted.** A helper whose _name_ looks like auth (`requireUser`,
  `withAuth`, `authenticateAdminRequest`) is resolved one level (same file, local import,
  Fastify `decorate`) and its body inspected:
  - it calls a recognised auth API, or it reads a credential (cookie / Authorization header /
    session) **and** has a rejection path (throw, 401/403, redirect, `return null`/`{ error }`)
    → **strong**, no finding;
  - it does neither → **notChecking**: reported (`wrapperDoesNotCheck`, medium confidence);
  - it cannot be resolved (package import, deeper indirection) → **unverified**: reported at
    **low confidence** with an explicit "unverified" message.
    Imports from known auth packages (`next-auth`, `@clerk/*`, `jsonwebtoken`, `jose`,
    `firebase-admin`, `@supabase/*`, `lucia`, `better-auth`, …) are strong whatever their local
    name. Names listed in `endpoints.authFunctions` are trusted.
- **`supabase.auth.getSession()` alone is weak** (it does not verify the JWT with the Auth
  server): reported as `weakAuth`, one severity step lower, medium confidence. `getUser()` /
  `getClaims()` are strong.
- **Middleware:** an unparseable `matcher` entry, or auth logic in an unresolvable import, yields
  _unknown_ coverage → `unverifiedAuth` at low confidence, never assumed protection.
- **Webhooks** are excluded from `unauthenticated-data-access` and checked by the new
  `endpoints/webhook-without-signature` rule: provider SDK verification, HMAC with
  `timingSafeEqual`, or a shared-secret header comparison count; otherwise high (writes) or
  medium, medium confidence (verification at a gateway is invisible).
- **More sensitive operations:** file-system writes (`fs.writeFile`, `unlink`, …) and outbound
  calls made with server secrets (SDK clients constructed with a secret env var or literal key,
  `fetch`/`axios` sending one) → `secretSpend` (medium/medium). Pure static responses remain
  non-sensitive. Read vs. write is decided by the API (and SQL text), not the HTTP method, so a
  GET that writes is still reported as a write.
- **Fastify encapsulation:** hooks and routes are keyed by the binding scope of the instance; an
  inline plugin passed to `register()` does not leak its hooks to sibling routes.
- **Rate limiting** confidence is capped at medium (low unless custom credential verification is
  visible), and the message states that gateway/WAF/CDN limits are invisible.
- **CORS:** a wildcard/reflected origin _without_ credentials on cookie-authenticated code is
  reported at low/low (`permissiveOnCookieRoute`).

The parser stays the TypeScript compiler API (ADR-0001), not ts-morph: ts-morph wraps the same
parser, and the type-checking `Project` it is built around is what ADR-0001 rejected for speed.
