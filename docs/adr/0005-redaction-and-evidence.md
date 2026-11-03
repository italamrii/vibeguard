# ADR-0005: Redaction is enforced by the type system, with a scrubber as backstop

- Status: Accepted
- Date: 2026-11-03

## Context

Hard requirement: never print a full secret in any output. Show the first 4 characters
and the length. A secrets scanner that leaks secrets into CI logs, SARIF uploads or
Markdown comments is worse than no scanner.

## Decision

1. `Redacted` is a **branded string type**. `Finding.evidence` is `Redacted`, and only two
   functions produce one:
   - `redactSecret(value)` → `abcd…[N chars]`. For values of 8 characters or fewer, it gives
     `…[N chars]`, because 4 characters of a short secret is too much of it. Length is
     counted in code points.
   - `scrubText(text, { knownSecrets })` for free-form evidence such as code snippets. It
     redacts known secrets verbatim, then generic credential shapes: PEM private-key
     blocks, URL passwords, JWT-shaped tokens, and 20+ character tokens that contain a
     digit and have high Shannon entropy. All patterns have bounded quantifiers, and a
     ReDoS test covers them.
2. **Defense in depth at the boundaries.** The engine scrubs finding `params` and
   rule-crash error messages. The CLI scrubs unexpected internal errors.
3. **Canary tests** (added with the secrets family) build fake secrets at runtime, scan
   them, render every format in both locales, and assert that no full secret appears in
   any output.

## Consequences

- A rule author who passes a raw string as evidence gets a compile error.
- The scrubber can over-redact a snippet, for example a long random-looking asset hash. We
  accept that: the snippet stays understandable and the cost of under-redaction is much higher.
- Absolute paths of the scan root are never printed in reports, because they leak local
  usernames.
