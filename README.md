# VibeGuard

VibeGuard is a local, read-only static scanner for the security flaws that AI-generated
("vibe-coded") web apps commonly ship with. It targets Next.js, React and Node (Express,
Fastify) apps on Supabase or Firebase, and checks three things:

1. **Secrets**: hardcoded provider keys, private keys, committed `.env` files, and secrets
   exposed to the browser through `NEXT_PUBLIC_` / `VITE_` variables.
2. **Supabase Row Level Security**: tables without RLS, RLS with no policies,
   `USING (true)` policies, RLS-bypassing views and `SECURITY DEFINER` functions, and the
   `service_role` key in client code.
3. **Unauthenticated endpoints**: route handlers, API routes, server actions and
   Express/Fastify routes that touch data with no auth check; unsigned webhooks; CORS that
   reflects any origin with credentials; and login routes without rate limiting.

It is meant for developers who built an app quickly (often with an AI assistant) and want a
fast, offline check before they ship, and for CI pipelines that want to stop the worst
mistakes from being merged.

> **Scan only code you own or are authorized to assess.** VibeGuard is a tool for checking
> your own projects. It is not for scanning other people's code without permission.

**Strictly local and read-only.** VibeGuard never modifies the scanned project, never makes
network calls, and never sends code or findings anywhere. It never runs code from the
project it scans. **Secrets are never printed in full.** Every output (terminal, JSON,
SARIF, Markdown) shows only the first 4 characters and the length, for example
`sk_l…[107 chars]`.

> **Status: 0.1.0, not yet published to npm.** Until the first release, run it from source
> (see [Run from source](#run-from-source)). The `npx` commands below work once the package
> is published.

## Quickstart

Requires Node.js 20.19 or later.

```bash
npx @italamrii/vibeguard scan .
```

```bash
npx @italamrii/vibeguard scan ./my-app --format markdown --output ../vibeguard-report.md
```

```bash
npx @italamrii/vibeguard scan ./my-app --lang ar
```

The package is `@italamrii/vibeguard`; the command it installs is `vibeguard`.
`vibeguard rules` lists every rule with its default severity.

### Example output

This is real output from one of the intentionally vulnerable fixture apps in this
repository (`fixtures/vite-firebase-vuln`). The keys in it are fake, and VibeGuard redacts
them anyway. The output is shortened where marked with `…`.

```text
VibeGuard security report
Scan only code you own or are authorized to assess.

! PARTIAL COVERAGE: some files could not be fully analysed (see the scan diagnostics). Findings for affected tables have lowered confidence.

.env
   CRITICAL  Environment file with values is committed (or not gitignored)  secrets/env-file-committed
    Location: .env:2:1
    .env is tracked by git and contains 5 non-empty value(s).
    Evidence: .env
    Confidence: High

   CRITICAL  Secret exposed to the browser through a public env variable  secrets/client-exposed-env
    Location: .env:7:1
    VITE_STRIPE_SECRET_KEY is inlined into client JavaScript and its value is a Stripe live secret key.
    Evidence: sk_l…[107 chars]
    Confidence: High
…
api/delete-account.ts
   CRITICAL  Endpoint reads or changes data without an authentication check  endpoints/unauthenticated-data-access
    Location: api/delete-account.ts:7:1
    ANY /api/delete-account modifies data with a privileged client (firestore .delete()) and has no authentication check: anyone can call it.
    Evidence: export default async function handler(req: VercelRequest, res: VercelResponse) {
    Confidence: High
…
src/lib/admin.ts
   CRITICAL  Supabase service_role key used in client-side code  supabase/service-role-in-client
    Location: src/lib/admin.ts:6:3
    SUPABASE_SERVICE_ROLE_KEY (service-role key) is referenced in client-side code (Vite src/).
    Evidence: import.meta.env.SUPABASE_SERVICE_ROLE_KEY
    Confidence: High
…
How to fix
  secrets/provider-key  Hardcoded provider credential
    1) Revoke and rotate the credential in the provider dashboard now; assume it is compromised. 2) Load it from an environment variable on the server only (never with a NEXT_PUBLIC_/VITE_ prefix). …
    Docs: https://github.com/italamrii/vibeguard/blob/main/docs/rules/secrets/provider-key.md
…
Scan diagnostics
  warn  Supabase is used but no SQL migrations were found (**/supabase/migrations). Tables created in the Supabase dashboard are invisible to VibeGuard, so Row Level Security could NOT be checked. Export the schema with `supabase db pull` and commit the migrations.

Summary: Findings: 16 (10 Critical, 4 High, 2 Medium)
Files scanned: 14 (75 ms)
```

Every finding has a severity (how bad it is if real) and a **confidence** (how sure
VibeGuard is). Low-confidence findings are shown and labelled, not hidden. Use
`--min-confidence medium` to hide them.

## Output formats and languages

| Flag                | Output                                                                                                                        |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `--format terminal` | Human-readable, grouped by file (default).                                                                                    |
| `--format json`     | Machine-readable; contract in [`schema/findings.v1.schema.json`](schema/findings.v1.schema.json).                             |
| `--format sarif`    | SARIF 2.1.0 for GitHub code scanning and other SARIF viewers ([ADR-0014](docs/adr/0014-sarif-mapping.md)).                    |
| `--format markdown` | A report for PR comments or issues.                                                                                           |
| `--lang en` / `ar`  | English or Arabic. Arabic Markdown and SARIF help are right-to-left safe ([ADR-0013](docs/adr/0013-arabic-rtl-rendering.md)). |
| `--output <file>`   | Write to a file. The file must be outside the scanned project, so VibeGuard never writes into the code it scans.              |

Terminals handle right-to-left text inconsistently, so `--lang ar` in the terminal prints a
short bilingual header and keeps the finding details in English. Markdown and SARIF
reports are fully Arabic.

## Exit codes

| Code | Meaning                                                                                |
| ---- | -------------------------------------------------------------------------------------- |
| `0`  | Scan complete. No unsuppressed finding at or above `--fail-on` (default `high`).       |
| `1`  | Scan complete. At least one unsuppressed finding at or above `--fail-on`.              |
| `2`  | Usage or configuration error.                                                          |
| `3`  | **Scan incomplete** (a rule crashed or an internal error). Never treat this as a pass. |

`--fail-on none` disables `1` but never `3`. Details: [docs/exit-codes.md](docs/exit-codes.md).

## Configuration

VibeGuard reads `.vibeguard.yml` from the scan root, or the file given with `--config`.
Unknown keys are an error, so a typo cannot silently disable a check.

```yaml
version: 1
ignore:
  - 'e2e/**'
failOn: high # critical | high | medium | low | none
minConfidence: low # high | medium | low
rules:
  secrets/high-entropy: off
  supabase/permissive-policy: { severity: low }
supabase:
  migrationsDirs: [supabase/migrations]
endpoints:
  authFunctions: [requireUser] # your own auth helpers, once you have confirmed them
  rateLimitFunctions: [limiter]
```

Every option is in [docs/configuration.md](docs/configuration.md). Every rule id is listed,
with what it detects and its known false positives, in [docs/rules](docs/rules/README.md).

## Suppressing a finding

Suppress a finding in the code, next to it, with the rule id **and a reason**:

```ts
// vibeguard-ignore-next-line endpoints/unauthenticated-data-access -- public product catalogue, read-only by design
export async function GET() {
```

- `vibeguard-ignore-next-line <rule-id> -- <reason>` covers the next line.
  `vibeguard-ignore-line` covers its own line, and `vibeguard-ignore-file` the whole file.
- The marker works in any comment syntax: `//`, `/* */`, `#` (YAML, `.env`) and `--` (SQL).
- **The reason is required** (at least 10 characters). A suppression without a reason or
  with an unknown rule id suppresses nothing, and it is reported as a diagnostic.
- Suppressed findings are not shown in terminal output. They are kept in JSON, listed with
  their reason in Markdown, and emitted in SARIF as in-source `suppressions` with the reason
  as the justification.

Design: [ADR-0004](docs/adr/0004-suppression-design.md).

## CI and GitHub code scanning

VibeGuard runs offline, so it needs nothing in CI beyond Node. This workflow fails the
build on high or critical findings and uploads the results to GitHub code scanning. Code
scanning is free for public repositories. Private repositories need GitHub Advanced
Security.

```yaml
name: VibeGuard
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write # for the SARIF upload

jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Scan
        # A pull request controls its own .vibeguard.yml and could switch rules off.
        # For untrusted contributions, pass --config from a trusted location instead.
        run: npx --yes @italamrii/vibeguard@0.1.0 scan . --format sarif --output "$RUNNER_TEMP/vibeguard.sarif" --fail-on high
      - name: Upload to code scanning
        if: always() # upload even when the scan step failed on findings
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ runner.temp }}/vibeguard.sarif
          category: vibeguard
```

Pin the version (`@0.1.0`) so an update cannot change your build. Each SARIF rule carries
a `security-severity` score and CWE tags, so GitHub ranks alerts correctly. Findings keep
stable fingerprints when unrelated lines move.

## Supported frameworks

| Area      | Supported in v1                                                                                                                                                               |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Languages | TypeScript and JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`), SQL migrations, `.env` files, JSON, YAML.                                                           |
| Frontend  | Next.js (App and Pages Router), Vite, Create React App, Expo (public env prefixes and client/server classification).                                                          |
| Backend   | Next.js route handlers, API routes, server actions and `middleware.ts` / `proxy.ts`; Vercel functions; Express; Fastify.                                                      |
| Data      | Supabase (SQL migrations, `supabase-js`), Firebase / Firestore (client and Admin SDK), Prisma, Drizzle, Mongoose-style models, `pg` / `mysql`, D1/SQLite prepared statements. |

## What it cannot detect

VibeGuard reads your source code and nothing else. Read this list before you treat a clean
report as "secure". The full list, with reasons, is in
[docs/threat-model.md](docs/threat-model.md).

- **Anything outside the repository.** Tables, policies and RLS settings changed in the
  Supabase dashboard and never exported to migrations; Firebase Security Rules deployed
  from the console; auth, rate limits or signature checks done by a gateway, WAF, CDN or
  hosting platform.
- **Authorization logic.** It checks whether an endpoint authenticates the caller. It does
  not check whether that caller may act on a specific record (IDOR, roles, tenants).
- **Git history.** A secret deleted in a later commit is invisible. Use a history scanner
  once, and rotate anything it finds.
- **Whether a key is live.** VibeGuard never contacts providers.
- **Assembled or obfuscated secrets** (concatenated, base64-wrapped, built at runtime), and
  random tokens in variables with neutral names.
- **Code paths it cannot follow.** It follows calls one level deep and has no full import
  graph. Routes registered dynamically, or by frameworks it does not model (Hono, NestJS,
  tRPC, GraphQL resolvers), are not discovered.
- **Other vulnerability classes.** XSS, SQL injection, SSRF, dependency vulnerabilities and
  similar are out of scope for v1, which has exactly three rule families.

## Accuracy

VibeGuard is tested against six intentionally vulnerable and clean fixture apps in this
repository. The clean apps must produce zero findings, and every expected finding must be
found. The per-rule results are in [docs/accuracy.md](docs/accuracy.md), including the
known misses.

**Fixture numbers are not real-world numbers.** The fixtures were written by the same
people who wrote the rules. They show the rules behave as designed and catch regressions.
They do not estimate precision or recall on your code. Validation on real projects is
reported separately, as counts only, in the same document.

Performance: a synthetic 5,000-file project scans in 3 to 4 seconds on the development
machine (`npm run bench`).

## Run from source

```bash
git clone https://github.com/italamrii/vibeguard.git
```

```bash
cd vibeguard && npm ci && npm run build
```

```bash
node dist/cli/index.js scan /path/to/your/project
```

## Documentation

- [Rules](docs/rules/README.md): one page per rule (what it detects, false positives, how
  to fix and suppress)
- [Threat model and known limitations](docs/threat-model.md)
- [Configuration](docs/configuration.md) · [Exit codes](docs/exit-codes.md)
- [Fixture accuracy](docs/accuracy.md)
- [Architecture decision records](docs/adr/README.md)
- [Dependencies and licenses](docs/dependencies.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) ·
  [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
