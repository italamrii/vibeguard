# ADR-0004: Inline suppressions require a rule id and a reason

- Status: Accepted
- Date: 2026-11-03

## Context

Every static analyzer produces some findings that are acceptable in context: a public
read-only lookup table, an intentionally public webhook. Users need to silence those. On
many teams, though, suppressions become a way to make CI green without anyone thinking
about it.

## Decision

Syntax, recognized inside any comment style (`//`, `/* */`, `#`, `--`, `{/* */}`, `<!-- -->`):

```
vibeguard-ignore-next-line <rule-id>[, <rule-id>…] -- <reason>
vibeguard-ignore-line      <rule-id>[, <rule-id>…] -- <reason>
vibeguard-ignore-file      <rule-id>[, <rule-id>…] -- <reason>
```

Rules:

- **A reason is mandatory**, after `--`, and must be at least 10 characters.
- **Rule ids are mandatory and must exist.** There is no wildcard and no blanket
  `vibeguard-ignore`.
- An invalid directive **suppresses nothing** and produces an `invalid-suppression`
  warning that names the problem.
- A valid directive that matches no finding produces an `unused-suppression` warning, so
  stale waivers get cleaned up.
- `next-line` skips over other stacked directives, so several can sit above one line.
- Suppressed findings are **not deleted**. They stay in JSON (with `suppression.reason`)
  and SARIF (`suppressions[].justification`, `kind: inSource`), so they remain auditable.
  Terminal and Markdown reports show the count, and Markdown lists them in a
  "Suppressed findings" section.
- Suppressions never affect the exit code. Only unsuppressed findings count toward `--fail-on`.

## Consequences

- Matching is textual on the raw line. A string literal containing the marker would be
  treated as a directive. We accept that, because the marker is unusual and the failure mode
  is a visible warning.
- Config-level rule toggles (`rules: { id: off }`) remain the tool for disabling a rule
  project-wide. Those are visible in a reviewed file and need no reason field.
