import { jsonReporter } from './json.ts';
import { markdownReporter } from './markdown.ts';
import { sarifReporter } from './sarif.ts';
import type { Reporter } from './reporter.ts';
import { terminalReporter } from './terminal.ts';

/** Reporter registry. Adding a format means adding a module and one entry here. */
export const REPORTERS: ReadonlyMap<string, Reporter> = new Map(
  [terminalReporter, jsonReporter, sarifReporter, markdownReporter].map((r) => [r.format, r]),
);

export const REPORT_FORMATS: readonly string[] = [...REPORTERS.keys()];
