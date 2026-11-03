import type { ScanResult } from '../core/engine/engine.ts';
import { meetsSeverity, type Severity } from '../core/findings/severity.ts';

/** Process exit codes. Documented in docs/exit-codes.md; treat as a public API. */
export const ExitCode = {
  /** No unsuppressed finding at or above the --fail-on threshold. */
  Ok: 0,
  /** At least one unsuppressed finding at or above the threshold. */
  FindingsAtThreshold: 1,
  /** Bad arguments or invalid configuration. Nothing was scanned. */
  UsageError: 2,
  /** A rule crashed or the scan otherwise could not complete. Results are partial. */
  ScanIncomplete: 3,
} as const;
export type ExitCode = (typeof ExitCode)[keyof typeof ExitCode];

/**
 * Incomplete beats findings: a partial scan must never be mistaken for a pass, and an
 * incomplete scan that happens to contain findings is still incomplete.
 */
export function exitCodeFor(result: ScanResult, failOn: Severity | 'none'): ExitCode {
  if (!result.complete) return ExitCode.ScanIncomplete;
  if (failOn === 'none') return ExitCode.Ok;
  const failing = result.findings.some((f) => !f.suppression && meetsSeverity(f.severity, failOn));
  return failing ? ExitCode.FindingsAtThreshold : ExitCode.Ok;
}
