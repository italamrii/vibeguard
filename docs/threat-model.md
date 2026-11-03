# Threat model and known limitations

VibeGuard is a **static, local, read-only** scanner. This document says what it is designed
to catch, what it cannot catch, and how it protects itself and its users.

**A clean report means "none of the patterns VibeGuard knows were found in the files it
could read". It does not mean the application is secure.** Every known blind spot is listed
in one place in [All blind spots](#all-blind-spots). The per-family sections below give the
details.

## All blind spots

The consolidated list. Each item is explained in its family section, and fixtures that
document a miss are annotated `vg-expect-miss`.

**Cross-cutting (all rules)**

1. **Only the repository is visible.** Dashboard settings, deployed config, environment
   variables on the host, gateways, WAFs, CDNs and platform protections are invisible.
2. **No execution.** Code, SQL functions, `DO` blocks and build steps are never run, so
   values and state computed at runtime are unknown.
3. **No full import graph.** Calls are followed one level; shared modules are classified
   "unknown" and not reported on (client/server, auth helpers, data access).
4. **Git history is not scanned.** Only the current working tree is read.
5. **Unsupported files and frameworks** produce no findings: binary files, files over
   5 MiB (skipped with a diagnostic), frameworks other than Next.js, Vite, Create React App,
   Expo, Vercel functions, Express and Fastify.
6. **The scanned repo's `.vibeguard.yml` and inline suppressions are trusted.** A malicious
   change can switch rules off or suppress findings (use `--config` from a trusted path in
   CI; suppressions are visible in reports and SARIF).
7. **Out of scope by design (v1):** authorization logic (IDOR, roles, tenants), XSS, SQL
   injection, SSRF, dependency vulnerabilities, Firebase Security Rules files, and any
   vulnerability class outside the three rule families.

**Secrets**

8. Obfuscated, concatenated, encoded or runtime-built secrets.
9. Random tokens in variables with neutral names; unknown provider formats without a
   secret-like name.
10. Whether a key is live or revoked (VibeGuard never contacts providers).
11. Server secrets passed into client code through props or shared modules.
12. Gitignored, untracked `.env` files are deliberately not checked for hardcoded secrets.
13. Human-chosen passwords in tests and throwaway CI/compose database passwords are skipped.

**Supabase**

14. Tables, policies and RLS changed in the dashboard and not exported to migrations.
15. Effects of PL/pgSQL (`DO` blocks, functions) and of statements that fail to parse: the
    tables become "unknown" (partial coverage), the effect is not applied.
16. Policy conditions are judged syntactically: a wrong but scoped-looking condition is not
    reported.
17. `search_path` assumed `public`; column privileges and `ALTER DEFAULT PRIVILEGES` not
    modelled; `storage` schema not analysed; views are not checked for which tables they
    read; materialized views are not analysed; `SECURITY DEFINER` function bodies are not
    analysed.

**Endpoints**

18. Auth, rate limits, CORS and webhook signature checks done by infrastructure.
19. Custom auth helpers that cannot be inspected (reported as unverified, low confidence).
20. Dynamically registered routes and unmodelled frameworks (Hono, NestJS, tRPC, GraphQL).
21. Presence, not dominance: an auth call anywhere in the handler counts.
22. Data access deeper than one helper, and custom repositories (`repo.save()`).
23. Routers mounted with auth in another file (can cause false positives).
24. Endpoint purpose (login, webhook) is inferred from paths and names.

## What VibeGuard protects against (its own risks)

| Risk                                                                         | Mitigation                                                                                                                                                                                                                                           |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The scanner leaks the secrets it finds (CI logs, SARIF uploads, PR comments) | Evidence has a branded `Redacted` type: first 4 characters plus length only. Params and errors are scrubbed. A canary test checks every format and language ([ADR-0005](adr/0005-redaction-and-evidence.md)).                                        |
| Scanned code executes inside the scanner                                     | No `require`/`import` of project files, no plugins from config ([ADR-0006](adr/0006-rule-registry.md)). The only subprocess is `git ls-files`, hardened against repo-controlled config such as `core.fsmonitor` ([ADR-0008](adr/0008-discovery.md)). |
| Hostile file content manipulates the report                                  | Control characters (ANSI escapes) and bidi overrides (Trojan Source) are escaped visibly. Markdown params are put in fence-safe code spans.                                                                                                          |
| A crash produces a silent pass                                               | Fail-closed: exit code 3 and an "incomplete" banner ([ADR-0009](adr/0009-exit-codes-fail-closed.md)).                                                                                                                                                |
| Symlinks escape the project, huge files exhaust memory                       | Symlinks are never followed. Files over 1 MiB are streamed; over 5 MiB, skipped with a diagnostic. All regexes have bounded quantifiers (ReDoS tests).                                                                                               |
| The scanned repo weakens its own scan via `.vibeguard.yml`                   | Documented. In CI, pass `--config` from a trusted path. Turning off build-output skipping only adds files.                                                                                                                                           |
| Network exfiltration                                                         | VibeGuard makes no network calls. Reports go to stdout or a file outside the scanned project.                                                                                                                                                        |

## Secrets family: what is detected

- Provider credentials with distinctive formats (`secrets/provider-key`): Stripe live
  and restricted keys; OpenAI; Anthropic; AWS access key IDs, plus AWS secret keys
  when named as such; GitHub classic and fine-grained tokens; Slack tokens and webhooks;
  SendGrid; Twilio API keys; Resend; Google API keys (Gemini keys escalated, Firebase web
  keys excluded); Supabase `service_role` JWTs and `sb_secret_` keys; passwords inside
  database URLs.
- Stripe test-mode keys (`secrets/provider-key-test`, low severity, a separate rule id so
  GitHub code scanning ranks them as low).
- Private keys (`secrets/private-key`): PEM blocks, including JSON-escaped and
  string-concatenated ones, and Google service-account files.
- Generic credentials (`secrets/high-entropy`): high-entropy or password values bound to
  secret-like names, hardcoded fallbacks (`process.env.X || '…'`), and literal keys passed
  to `jwt.sign`, `createHmac` and similar.
- `.env` files that are committed or not gitignored (`secrets/env-file-committed`), using
  real git state when available.
- Secrets inlined into client bundles (`secrets/client-exposed-env`): public-prefixed env
  vars (`NEXT_PUBLIC_`, `VITE_`, …) by name or value, `next.config` `env`, and Vite `define`.

## Secrets family: known limitations

- **Obfuscated or assembled secrets are missed**: concatenation, base64-wrapped values,
  values built at runtime. Detection is per literal (fixture `vg-expect-miss`).
- **Git history is not scanned.** A secret deleted in a later commit is invisible. Use a
  history scanner (gitleaks, trufflehog) once, and rotate anything found. (VibeGuard's own
  repository is checked with `npm run scan:history` before releases.)
- **No validity checking.** VibeGuard never contacts providers, by design, so it cannot tell
  a revoked key from a live one.
- **Unknown formats** fall back to the entropy rule, which needs a secret-like variable or
  key name. A random token in `const x = '…'` is not reported.
- **No import graph.** `secrets/client-exposed-env` relies on bundler conventions (public
  prefixes, config files). A server-only secret passed into a client component through
  props or a shared module is not traced.
- Gitignored, untracked `.env` files are deliberately not checked for hardcoded secrets,
  because that is where local secrets belong. They are still checked for client exposure.
- Human-chosen passwords in test files are skipped. Random-looking tokens in tests are
  reported with lowered confidence.

## Supabase family: what is detected

From SQL migrations (`**/supabase/migrations/*.sql`, or `supabase.migrationsDirs`), replayed in
filename order so that the final state wins:

- Tables in exposed schemas (`[api] schemas` in `supabase/config.toml`, default
  `public, graphql_public`) without Row Level Security, including RLS disabled later and
  policies that exist while RLS is off (`supabase/rls-disabled`). Tables whose privileges are
  revoked from `anon` and `authenticated` are treated as intentionally private.
- RLS enabled with no permissive policy (`supabase/rls-no-policies`, low severity).
- Policies that admit every row: `USING (true)` / `WITH CHECK (true)`, or conditions that
  only check that the caller is logged in. Severity depends on command, audience and the
  kind of table (`supabase/permissive-policy`).
- Views in exposed schemas without `security_invoker` (`supabase/security-definer-view`) and
  callable `SECURITY DEFINER` functions (`supabase/security-definer-function`), at medium/low
  confidence.
- The service-role key used in browser code: the env var referenced in a client module, or a
  client module importing a module that uses the key (`supabase/service-role-in-client`).

## Supabase family: known limitations

- **The dashboard blind spot.** Tables, policies and RLS settings changed in the Supabase
  dashboard and never exported to migrations are invisible. If the project uses Supabase but
  has no migrations, the report says so explicitly (`no-migrations`) and is marked as partial
  coverage. Run `supabase db pull` and commit the result.
- **PL/pgSQL is not executed.** `DO` blocks and functions that change RLS or policies make the
  affected tables _unknown_ (a `dynamic-sql` notice and partial coverage), but the effect itself
  is not applied (fixture `vg-expect-miss`).
- **Unparseable statements** (`parse-failed`) make the tables they mention unknown. Findings on
  them have low confidence.
- **Policy expressions are judged syntactically.** Only always-true and "is logged in" conditions
  are reported. A scoped-looking but wrong condition (`owner = owner`, a join that leaks rows) is
  not proven safe or unsafe.
- `search_path` is assumed to be `public` for unqualified names. Column-level privileges and
  `ALTER DEFAULT PRIVILEGES` are not modelled. Only `REVOKE ALL` (or `REVOKE EXECUTE` for
  functions) counts as making an object private.
- Client/server classification has no transitive import graph (ADR-0010). Shared modules are
  "unknown" and are not reported on.
- Storage bucket policies (`storage.objects`) are only checked if the policies appear in an
  exposed schema. The `storage` schema is not exposed by default and is not analysed.

## Endpoints family: what is detected

- Route handlers, API routes, Vercel functions, server actions, and Express/Fastify routes that
  read or modify data, write files, or call external services with server secrets, and have no
  verified authentication (`endpoints/unauthenticated-data-access`). Auth is three-valued:
  confirmed (no finding), weak (`getSession()` only: lower severity), or unverified (helper we
  cannot inspect: low confidence). Helpers named like auth are trusted only after their body is
  inspected ([ADR-0012](adr/0012-endpoint-auth-detection.md)).
- Next.js `middleware.ts` / `proxy.ts` counts only if it verifiably authenticates and blocks, and
  its matcher covers the route. Express `app.use` ordering and Fastify plugin encapsulation are
  respected.
- Webhook receivers that do not verify the sender's signature
  (`endpoints/webhook-without-signature`).
- CORS that allows credentials with a reflected or wildcard origin, and permissive origins on
  cookie-authenticated code (`endpoints/cors-wildcard-credentials`).
- Custom login/signup/reset/OTP endpoints and server actions without a rate limiter
  (`endpoints/auth-route-no-rate-limit`, medium/low confidence only).

## Endpoints family: blind spots (by design or by limitation)

- **Auth enforced at the gateway or infrastructure level** (API gateway, Cloudflare Access, Vercel
  deployment protection, a reverse proxy with OIDC, service mesh): invisible. Endpoints protected
  only that way are reported. Suppress with the reason, or list the guard in config.
- **Rate limits and webhook signature checks done by infrastructure** (WAF, CDN, gateway):
  invisible. This is why both rules never report high confidence.
- **Custom auth helpers we cannot recognise:** a guard in a package, behind two levels of
  indirection, or with an unusual shape (no credential read visible) is reported as
  _unverified_ (low confidence) or _wrapper does not check_ (medium). Add it to
  `endpoints.authFunctions` once you have confirmed it.
- **Dynamic route registration:** routes built in loops, from config objects, file-system
  routers other than Next.js, or registered through framework wrappers we do not model (Hono,
  NestJS decorators, tRPC procedures, GraphQL resolvers) are not discovered. No discovery means
  no finding, which is a false negative.
- **IDOR and authorization logic are explicitly out of scope.** "Is the caller logged in" is
  checked. "May this caller act on this record" (ownership, roles, tenants) is not.
- **Presence, not dominance:** a verified auth call anywhere in the handler counts, even if
  the write happens before it or its result is ignored.
- Calls are followed one level. Data access deeper than one helper is not seen, and the endpoint
  then looks harmless (false negative).
- Sinks are recognised by API shape: Supabase, Firestore, Prisma, Drizzle, Mongoose-style models,
  `pg`/`mysql` `.query()`, prepared statements (D1/SQLite), `sql` tags, `fs` writes, SDK clients
  built with secrets. Custom repositories (`repo.save()`) are invisible.
- Routers mounted from another file with auth at the mount point (`app.use('/x', auth, router)`)
  do not propagate. Those routes can be reported as unauthenticated. Add `router.use(auth)` in the
  router file (recommended anyway) or suppress.
