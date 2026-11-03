# ADR-0009: Exit codes and fail-closed scanning

- Status: Accepted
- Date: 2026-11-03

## Context

CI gates on the exit code. The most dangerous failure mode for a security scanner is
**fail-open**: a rule crashes on an unusual file, produces nothing, and the build goes
green.

## Decision

| Code | Meaning                                                                                                                        |
| ---- | ------------------------------------------------------------------------------------------------------------------------------ |
| 0    | Scan complete; no unsuppressed finding at or above `--fail-on` (default `high`).                                               |
| 1    | Scan complete; at least one unsuppressed finding at or above `--fail-on`.                                                      |
| 2    | Usage error: bad flag, invalid or unknown config, path missing, or `--output` inside the scanned project. Nothing was scanned. |
| 3    | Scan incomplete: a rule crashed, emitted an invalid finding, or an internal error occurred. **Takes precedence over 1.**       |

- Every rule runs in isolation. An exception becomes an `error` diagnostic that names the
  rule, and the scan is marked `complete: false`. All reporters show an explicit
  "SCAN INCOMPLETE" banner, and JSON and SARIF carry the flag.
- `--fail-on none` never fails on findings, but still exits 3 on an incomplete scan.
- **Read-only also covers reports.** `--output` may not resolve, after symlink resolution,
  to a path inside the scanned project. Users write reports elsewhere (for example
  `$RUNNER_TEMP`) or redirect stdout.

## Consequences

- An unusual project can produce exit 3 until the bug is fixed or the file is excluded via
  `ignore`. We prefer a loud failure to a false pass.
- Exit codes are public API and are documented in `docs/exit-codes.md`.
