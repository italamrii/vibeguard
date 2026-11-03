# ADR-0006: Static rule registry; no runtime plugin loading

- Status: Accepted
- Date: 2026-11-03

## Context

Adding a rule must not require touching core code. A common way to get that is runtime
plugins loaded from config (`plugins: ["./my-rule.js"]`). However, `.vibeguard.yml` lives
inside the **scanned repository**, which may be untrusted, such as a pull request from a
fork in CI. Loading code named by that file would let the scanned code execute inside the
scanner, with CI credentials.

## Decision

- A rule is a module exporting a `Rule` (`meta` plus `detect(ctx)`). `src/rules/index.ts`
  holds the only list of rules. Adding a rule means adding one module and one line in that
  list. `src/core/**` never names a rule or a rule family.
- The engine validates rule metadata at startup: the id format `<family>/<kebab-name>`,
  the id prefix matching the family, unique ids, and a non-empty message set.
- **There is no dynamic loading** of rules, reporters or anything else from config, the
  environment or the scanned project.
- `RuleContext` is the only capability a rule receives: read-only file listing, text,
  line streaming, a memoized AST, and diagnostics. It offers no write, process or network
  access. That is a convention we review for; it is not a sandbox.

## Consequences

- Third-party rules require a fork or an upstream contribution in v1. If demand appears, a
  future ADR can add plugins loaded only from CLI flags or the user's home directory,
  never from the scanned tree.
- The scanned repo's config can still **disable** rules. The threat model covers this,
  and CI users are told to pass `--config` from a trusted location.
