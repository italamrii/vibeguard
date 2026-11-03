# Exit codes

VibeGuard's exit codes are a public API. They will not change meaning within a major version.

| Code | Meaning                                                                                                                       |
| ---- | ----------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Scan complete. No unsuppressed finding at or above `--fail-on` (default `high`).                                              |
| `1`  | Scan complete. At least one unsuppressed finding at or above `--fail-on`.                                                     |
| `2`  | Usage error: invalid flag, invalid config, unknown rule id in config, missing path, or `--output` inside the scanned project. |
| `3`  | **Scan incomplete.** A rule crashed or an internal error occurred. Results are partial and must not be treated as a pass.     |

`3` takes precedence over `1`. `--fail-on none` disables `1` but never `3`.

Rationale: [ADR-0009](adr/0009-exit-codes-fail-closed.md).
