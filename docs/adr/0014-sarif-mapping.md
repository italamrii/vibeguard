# ADR-0014: SARIF 2.1.0 mapping for GitHub code scanning

- Status: Accepted
- Date: 2026-11-03

## Decision

| VibeGuard          | SARIF                                                                                                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rules that ran     | `tool.driver.rules[]` with `id`, PascalCase `name`, `shortDescription`, `fullDescription`, `help.text`, `help.markdown` (vulnerable and fixed code), `helpUri` (rule doc), `defaultConfiguration.level`                                     |
| Rule severity      | `properties.security-severity` (critical 9.5, high 8.0, medium 5.5, low 2.5), which GitHub maps to its severity bands. Also `properties.tags`: `security`, the family, `external/cwe/cwe-N` (max 20)                                        |
| Finding severity   | `result.level`: critical/high → `error`, medium → `warning`, low → `note`. Also `result.properties.severity` and `security-severity` (per result; GitHub ranks by the rule-level value)                                                     |
| Confidence         | `result.properties.confidence`                                                                                                                                                                                                              |
| Location           | `artifactLocation.uri`: relative to the scan root, percent-encoded per segment, with `uriBaseId: "%SRCROOT%"`. **No absolute paths**, so local usernames never leak. `region` has 1-based lines and columns, `columnKind: "utf16CodeUnits"` |
| Evidence           | `region.snippet.text`: the engine's redacted evidence only (ADR-0005). The redaction canary covers SARIF in both languages                                                                                                                  |
| Fingerprint        | `partialFingerprints["vibeguard/v1"]`: the engine's line-independent fingerprint, so alerts survive unrelated edits                                                                                                                         |
| Inline suppression | `suppressions: [{ kind: "inSource", status: "accepted", justification: <reason> }]`                                                                                                                                                         |
| Diagnostics        | `invocations[0].toolExecutionNotifications[]` with `descriptor.id` = diagnostic code                                                                                                                                                        |
| Incomplete scan    | `executionSuccessful: false` and a `scan-incomplete` notification (level `error`)                                                                                                                                                           |
| Partial coverage   | `partial-coverage` notification (level `warning`) and `run.properties.partialCoverage`                                                                                                                                                      |
| Language           | `--lang` selects the language of descriptions and messages; `tool.driver.language` records it                                                                                                                                               |

**Limits.** GitHub accepts at most 25,000 results per run. Findings are sorted most severe first,
so the reporter keeps the first 25,000 and adds a `results-truncated` notification.
`checkGitHubSarif()` also checks the other documented limits: 10 MB gzip, 20 runs, 25,000
rules, 1,000 locations per result, 20 tags per rule, relative URIs, valid levels and numeric
`security-severity`.

**Validation.** Tests validate the output against the official OASIS SARIF 2.1.0 schema,
vendored at `test/vendor/` with a recorded SHA-256; tests never touch the network. They also
check the GitHub constraints. CI runs `npm run sarif:check` on the built CLI for every fixture app
in both languages. A real upload is a manual pre-release task (`code-scanning-upload.yml`,
`docs/release-checklist.md`), because code scanning needs a public repository or GitHub Advanced
Security.

## Consequences

- GitHub shows one severity per rule, from the rule-level `security-severity`. Per-occurrence
  severity overrides (a Stripe _test_ key is low within the critical `provider-key` rule) appear
  as `result.level` and in properties, but GitHub's severity column shows the rule default.
- Isolate characters in Arabic message text are invisible in GitHub's UI. Programs should read
  `ruleId` and `properties`, not parse messages.

## Amendment (2026-11-03): rule split for accurate GitHub severity

Stripe test-mode keys were the main case of a per-result severity (low) differing from its
rule's default (critical). They are now a separate rule, `secrets/provider-key-test`
(security-severity 2.5), so GitHub's per-rule severity is accurate for them. Remaining
per-result overrides (for example a Gemini key escalated to critical inside the medium Google
API key pattern) stay visible in `result.level` and `result.properties.security-severity`.
