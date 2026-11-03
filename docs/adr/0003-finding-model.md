# ADR-0003: Finding model with localized message IDs

- Status: Accepted
- Date: 2026-11-03

## Context

Findings must render in English and Arabic, in four formats (terminal, JSON, SARIF and
Markdown). Every finding needs severity, confidence, a precise location, redacted evidence,
an explanation, remediation (vulnerable and fixed patterns), CWE and references. GitHub code
scanning needs stable identities so alerts are not duplicated when lines shift.

## Decision

1. **Rules emit data, not prose.** A rule returns `FindingInput` objects:
   `{ location, messageId, params, evidence: Redacted, confidence, severity?, fingerprintKey? }`.
   The engine attaches `ruleId`, CWE and references from the rule's metadata, so a rule
   cannot misattribute a finding.
2. **Text lives with the rule, in every locale.** `RuleMeta.messages` and `RuleMeta.docs`
   use `Localized<T> = Record<Locale, T>`. A missing translation is a **compile error**, not
   a runtime fallback to English. Report chrome (headings, labels) lives in `src/i18n/ui.ts`
   under the same constraint.
3. **Severity and confidence are independent axes.** Severity is impact if the finding is
   real, from `critical` to `low`. Confidence is how sure the analysis is, from `high` to
   `low`. Low-confidence findings are always labelled and are shown by default
   (`minConfidence: low`). Hiding them is an explicit user choice, and the report states
   how many were hidden.
4. **Fingerprints exclude line numbers.** They are computed as
   `sha256(ruleId, file, fingerprintKey, occurrenceIndex)`. Rules supply a semantic key
   (for example `table:public.profiles`). The occurrence index separates identical keys
   in the same file. This maps to SARIF `partialFingerprints`.
5. **Params are untrusted.** Interpolated values (identifiers, table names, paths) come from
   the scanned code. The engine scrubs them for secrets, and reporters sanitize control and
   bidi characters and escape them per format.

## Consequences

- Adding a locale means extending `LOCALES`. The compiler then lists every string to
  translate.
- JSON output carries both the rendered `message` (in the chosen locale) and the stable
  `messageId` and `params`, so tooling does not need to parse prose.
- Rule authors write text twice. We accept that cost: Arabic output is a first-class
  requirement, not an afterthought.
