# ADR-0007: Fixtures are templates; fake secrets are assembled at build time

- Status: Accepted
- Date: 2026-11-03

## Context

The secrets rules need realistic test data: format-valid Stripe, OpenAI, AWS, GitHub,
Slack, SendGrid and Supabase keys, PEM private keys, and database URLs with passwords.
Committing such strings, even fake ones, causes real problems:

- **GitHub push protection** rejects pushes that contain provider-format tokens, and
  secret scanning raises alerts (and may notify providers, some of whom auto-revoke
  matching keys or contact the repository owner).
- Every other scanner pointed at this repository (gitleaks, trufflehog, VibeGuard itself)
  would report them, training users to ignore findings.
- Copy-pasted fixture keys end up in other projects, where they look real.

## Decision

1. **No secret-shaped literal is ever committed.** Not in fixtures, tests or docs.
2. Fixture apps live in `fixtures/<app>-{vuln,clean}/` as **templates** containing
   `{{FAKE:<kind>[:<label>]}}` tokens. `test/helpers/fake-secrets.ts` renders each token
   with a seeded PRNG (mulberry32), so values are deterministic per (kind, label), and the
   same label can be reused across files of one app. Provider prefixes are split in source
   (`j('sk', '_live_', …)`) so the generator file itself is not secret-shaped.
3. Values are **format-valid and high-entropy**, so they exercise the real detection path
   including the entropy and placeholder filters. They were never issued by any provider.
4. Documentation example credentials (AWS's `AKIA…EXAMPLE`, Stripe's docs test key) are
   produced the same way, so clean apps can show that they are _not_ reported.
5. Template dotfiles are stored as `dot_<name>` (`dot_gitignore`, `dot_env.local`) and
   renamed when materialised, so a fixture's `.gitignore` never affects this repository and
   template env files are not mistaken for real ones.
6. `buildFixtures()` writes each app outside the repository (a temp dir by default; the
   script refuses an output path inside the repo) and makes each app **its own git
   repository** with everything not ignored committed. Committed-file detection is then
   tested against real git state, not simulated flags.
7. Expected findings are annotated in place (`vg-expect: <rule-id>` on the line above;
   `vg-expect-miss: <rule-id> -- <reason>` for documented misses). Files that cannot hold
   comments use `vg-expectations.txt`. The accuracy harness matches on rule, file and line.
8. A **redaction canary** test renders every reporter in every locale for every vulnerable
   app and fails if any 12-character window of any generated secret appears in the output.
9. CI scans this repository with VibeGuard itself (`--fail-on low`), so a secret-shaped
   literal cannot be merged unnoticed.

## Consequences

- Reading a fixture template does not show the actual value. Run
  `npm run fixtures:build -- --out <dir>` to inspect the materialised apps.
- Adding a provider pattern means adding a generator kind as well as a pattern, which is
  intentional: the pattern's positive test uses it.
