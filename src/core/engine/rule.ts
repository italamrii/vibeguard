import type { Settings } from '../config/settings.ts';
import type { FileKind } from '../discovery/file-kind.ts';
import type { FileRecord } from '../discovery/walker.ts';
import type { Diagnostic, FindingInput } from '../findings/finding.ts';
import type { Severity } from '../findings/severity.ts';
import type { LineIndex } from '../parsing/text.ts';
import type { ParsedTs } from '../parsing/ts-parser.ts';
import type { Localized } from '../../i18n/locale.ts';

/**
 * Human-facing documentation for a rule, in every supported locale. Code samples are
 * shared across locales; only prose is translated.
 */
export interface RuleDocs {
  readonly title: Localized;
  /** One-paragraph explanation of the risk. */
  readonly summary: Localized;
  readonly remediation: {
    readonly text: Localized;
    readonly codeLanguage: string;
    readonly vulnerable: string;
    readonly fixed: string;
  };
}

export interface RuleMeta<M extends string = string> {
  /** `<family>/<kebab-name>`, e.g. `supabase/rls-disabled`. Stable: users reference it in config and suppressions. */
  readonly id: string;
  readonly family: string;
  readonly defaultSeverity: Severity;
  /** CWE identifiers (numbers only), most specific first. */
  readonly cwe: readonly number[];
  readonly references: readonly string[];
  readonly docs: RuleDocs;
  /** Per-occurrence messages, with `{param}` placeholders. */
  readonly messages: Readonly<Record<M, Localized>>;
}

export interface FileFilter {
  readonly kinds?: readonly FileKind[];
  readonly path?: (relPath: string) => boolean;
}

export interface TextFile {
  readonly text: string;
  readonly lines: LineIndex;
}

/**
 * Everything a rule may use. Rules get read-only, lazily-parsed views of the project;
 * they cannot write files, spawn processes or reach the network through this interface.
 */
export interface RuleContext {
  readonly root: string;
  readonly settings: Settings;
  files(filter?: FileFilter): readonly FileRecord[];
  file(relPath: string): FileRecord | undefined;
  /**
   * Whole-file text for files up to the streaming threshold. Returns `undefined` for
   * larger or binary files; use `lines()` for those.
   */
  readText(file: FileRecord): Promise<TextFile | undefined>;
  /** Line stream that works for any file size. Binary files yield nothing. */
  lines(file: FileRecord): AsyncIterable<{ readonly text: string; readonly line: number }>;
  /** Parse JS/TS/JSX/TSX. `undefined` for non-code or oversized files. */
  parseTs(file: FileRecord): Promise<ParsedTs | undefined>;
  /** Report a problem with the scan itself (not a finding). */
  diagnostic(d: Diagnostic): void;
}

export interface Rule<M extends string = string> {
  readonly meta: RuleMeta<M>;
  detect(ctx: RuleContext): Promise<readonly FindingInput<M>[]>;
}

/** Identity helper that preserves the message-id type parameter for inference. */
export function defineRule<M extends string>(rule: Rule<M>): Rule<M> {
  return rule;
}

export const RULE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\/[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
