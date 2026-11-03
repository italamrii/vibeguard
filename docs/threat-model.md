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
