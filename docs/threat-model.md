# Threat model and known limitations

VibeGuard is a **static, local, read-only** scanner. This document says what it is designed
to catch, what it cannot catch, and how it protects itself and its users. It grows with each
rule family.

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

- Provider credentials with distinctive formats (`secrets/provider-key`): Stripe live,
  restricted and test keys; OpenAI; Anthropic; AWS access key IDs, plus AWS secret keys
  when named as such; GitHub classic and fine-grained tokens; Slack tokens and webhooks;
  SendGrid; Twilio API keys; Resend; Google API keys (Gemini keys escalated, Firebase web
  keys excluded); Supabase `service_role` JWTs and `sb_secret_` keys; passwords inside
  database URLs.
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
  history scanner (gitleaks, trufflehog) once, and rotate anything found.
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
  read or modify data with no authentication signal (`endpoints/unauthenticated-data-access`).
  Severity depends on whether the access is privileged (service role / admin SDK), direct
  (ORM/SQL) or user-scoped (RLS applies) ([ADR-0012](adr/0012-endpoint-auth-detection.md)).
- CORS that allows credentials together with a reflected or wildcard origin, via `cors()`,
  `@fastify/cors`, manual headers, or `next.config` `headers()`
  (`endpoints/cors-wildcard-credentials`).
- Custom login/signup/reset/OTP endpoints and server actions without a rate limiter
  (`endpoints/auth-route-no-rate-limit`).

## Endpoints family: known limitations

- **An auth call counts if it is present, even if nothing depends on it.** A call whose result
  is ignored still counts as authentication.
- **Authorization is not checked.** IDOR, missing role checks and multi-tenant leaks are out of
  scope for v1.
- **Calls are followed one level only.** Same-file helpers and local imported functions are
  followed once. Deeper chains and middleware mounted from another file are not.
- Sinks are recognised by API shape (Supabase, Firestore, Prisma, Drizzle, Mongoose-style
  models, `pg`, `sql` tags). Custom data layers (`repo.save()`) are not recognised.
- Express routers mounted with auth in another file can be reported as unauthenticated (false
  positive). Add `router.use(auth)` in the router file, or suppress with a reason.
- Rate limiting is recognised by library or name. An in-house limiter needs
  `endpoints.rateLimitFunctions`. Limits enforced by the platform (WAF, API gateway) are not
  visible.
- `next.config` CORS headers are matched per file, not per `source` path.
