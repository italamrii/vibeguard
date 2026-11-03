# ADR-0013: Rendering Arabic: isolated LTR runs in files, no Arabic in terminals

- Status: Accepted
- Date: 2026-11-03

## Context

Reports must be available in Arabic (`--lang ar`). Arabic prose in a security report is full
of left-to-right runs: rule ids, file paths, env vars, product names and code (`.env.local`,
`NEXT_PUBLIC_`, `auth.uid()`, `USING (true)`). Under the Unicode Bidirectional Algorithm, the
neutral characters in those runs (dots, slashes, brackets, colons) take the direction of the
surrounding Arabic. So ".env" displays as "env.", "(Postgres 15)" flips its parentheses, and
`file.ts:12:3` scrambles. Phase (a) wrapped only interpolated parameters; the remaining Arabic
prose still had the ".env / .gitignore" bug.

Terminals are worse. Most terminal emulators do not implement the bidi algorithm or Arabic
shaping at all: letters appear disconnected and in reverse order. A few have partial or
opt-in support. The same bytes look correct in one terminal and garbled in the next, and we
cannot detect which.

## Decision

**Files (Markdown, SARIF, JSON)**

- Every LTR run inside Arabic prose is wrapped in LEFT-TO-RIGHT ISOLATE … POP DIRECTIONAL
  ISOLATE (U+2066 … U+2069) by `isolateLtrRuns` (`src/i18n/bidi.ts`).
  - A run is maximal: Latin letters, digits and ASCII punctuation, plus single spaces between
    them, so "Row Level Security" stays one unit.
  - Sentence punctuation at the end of a run stays outside the isolate, so it remains Arabic
    punctuation.
  - Unbalanced brackets at either edge stay outside, since they belong to an Arabic
    parenthetical.
  - A leading dot stays inside the run, which is what fixes ".env".
- Templates are isolated before interpolation (`isolateTemplate`). Parameter values are
  isolated by the reporter.
- Markdown additionally wraps the document in `<div dir="rtl">` and every code block in
  `<div dir="ltr">`. Inline code is a code span with the isolates _outside_ the backticks, so
  copy-paste stays clean.
- User-written text of unknown direction (suppression reasons) uses FIRST STRONG ISOLATE.
- **A test fails if any Latin letter or digit sits outside an isolate on a line that contains
  Arabic** (`findUnisolatedLtr`). It runs on the help text of every rule, on every UI string,
  on a synthetic report with hostile parameters, and on the Arabic report of every fixture app.
- The isolates are invisible format characters. They are part of the rendered `message` in JSON
  and SARIF output. Programs should use `messageId` and `params`, which never contain them.

**Terminal**

- **We do not claim Arabic works in terminals.** With `--format terminal --lang ar` the report
  body is printed in **English**, preceded by a two-line hint (English, then Arabic) that points
  to `--format markdown` (or json/sarif) for an Arabic report.
- CLI error messages with `--lang ar` print the English line followed by the Arabic line, so a
  message is never _only_ available in a form the terminal may garble.
- `--help` stays English (commander renders it before `--lang` is known), as do commander's
  own argument errors. Both are listed as known gaps.

**Proofreading**

- Arabic strings stay next to their English source in each rule and in `src/i18n/ui.ts`, so the
  compiler keeps rejecting a missing translation (ADR-0003). `npm run arabic-review` generates
  `docs/arabic-review.md`, a single table of every Arabic string next to its English source.
  A test fails when that file is out of date.

## Consequences

- Arabic Markdown renders correctly wherever the renderer implements UAX #9 isolates (GitHub,
  VS Code, all current browsers). Very old renderers may show isolates as boxes.
- Arabic terminal output may be reconsidered behind an explicit opt-in (for example
  `VIBEGUARD_TERMINAL_BIDI=1`) if users with bidi-capable terminals ask for it. It is not the
  default.
