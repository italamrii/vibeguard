import type { MessageParams } from '../../i18n/locale.ts';
import type { Redacted } from '../redaction/redact.ts';
import type { Confidence, Severity } from './severity.ts';

/** 1-based line and column, posix path relative to the scan root. */
export interface SourceLocation {
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

/**
 * What a rule reports. The engine attaches rule metadata (id, CWE, references), so a
 * rule cannot misattribute its findings.
 */
export interface FindingInput<M extends string = string> {
  readonly location: SourceLocation;
  readonly messageId: M;
  readonly params?: MessageParams;
  readonly evidence: Redacted;
  readonly confidence: Confidence;
  /** Overrides the rule's default severity for this specific occurrence. */
  readonly severity?: Severity;
  /**
   * Stable, line-independent identity for this occurrence (e.g. "table:public.profiles").
   * Must not contain the raw secret; it is hashed but still treat it as sensitive.
   * Defaults to messageId + evidence.
   */
  readonly fingerprintKey?: string;
}

export interface Suppression {
  readonly reason: string;
  /** Line of the suppression comment. */
  readonly line: number;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly location: SourceLocation;
  readonly messageId: string;
  readonly params: MessageParams;
  readonly evidence: Redacted;
  readonly cwe: readonly number[];
  readonly references: readonly string[];
  /** Hex sha256 prefix; stable across unrelated edits that shift line numbers. */
  readonly fingerprint: string;
  readonly suppression?: Suppression;
}

export type DiagnosticLevel = 'error' | 'warning' | 'info';

/**
 * Something about the scan itself rather than the scanned code. Any `error` diagnostic
 * marks the scan incomplete (exit code 3): we never report a partial scan as clean.
 */
export interface Diagnostic {
  readonly level: DiagnosticLevel;
  readonly code: DiagnosticCode;
  readonly params: MessageParams;
  readonly file?: string;
  readonly line?: number;
}

export type DiagnosticCode =
  | 'rule-crashed'
  | 'file-unreadable'
  | 'file-too-large'
  | 'parse-failed'
  | 'invalid-suppression'
  | 'unused-suppression'
  | 'symlink-skipped'
  | 'git-unavailable'
  | 'no-migrations'
  | 'dynamic-sql';
