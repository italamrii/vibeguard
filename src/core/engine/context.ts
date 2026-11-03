import { readFile } from 'node:fs/promises';
import type { Settings } from '../config/settings.ts';
import { CODE_KINDS } from '../discovery/file-kind.ts';
import type { FileRecord } from '../discovery/walker.ts';
import type { Diagnostic } from '../findings/finding.ts';
import { isBinaryFile, LineIndex, STREAM_THRESHOLD_BYTES, streamLines } from '../parsing/text.ts';
import { parseSql, type ParsedSql } from '../parsing/sql-parser.ts';
import { parseTypeScript, type ParsedTs } from '../parsing/ts-parser.ts';
import type { FileFilter, RuleContext, TextFile } from './rule.ts';

/** Minified or generated code: very long lines. Not worth an AST and a common FP source. */
const MAX_AVG_LINE_LENGTH_FOR_AST = 500;

/**
 * Shared, memoised project view. One instance per scan; all rules share the caches so a
 * file is read and parsed at most once regardless of how many rules look at it.
 */
export class ProjectContext implements RuleContext {
  readonly root: string;
  readonly settings: Settings;
  private readonly all: readonly FileRecord[];
  private readonly byPath: ReadonlyMap<string, FileRecord>;
  private readonly textCache = new Map<string, Promise<TextFile | undefined>>();
  private readonly tsCache = new Map<string, Promise<ParsedTs | undefined>>();
  private readonly sqlCache = new Map<string, Promise<ParsedSql | undefined>>();
  private readonly diags: Diagnostic[] = [];

  constructor(root: string, settings: Settings, files: readonly FileRecord[]) {
    this.root = root;
    this.settings = settings;
    this.all = files;
    this.byPath = new Map(files.map((f) => [f.relPath, f]));
  }

  get diagnostics(): readonly Diagnostic[] {
    return this.diags;
  }

  files(filter: FileFilter = {}): readonly FileRecord[] {
    const { kinds, path } = filter;
    return this.all.filter(
      (f) =>
        (kinds === undefined || kinds.includes(f.kind)) && (path === undefined || path(f.relPath)),
    );
  }

  file(relPath: string): FileRecord | undefined {
    return this.byPath.get(relPath);
  }

  readText(file: FileRecord): Promise<TextFile | undefined> {
    let p = this.textCache.get(file.relPath);
    if (!p) {
      p = this.loadText(file);
      this.textCache.set(file.relPath, p);
    }
    return p;
  }

  private async loadText(file: FileRecord): Promise<TextFile | undefined> {
    if (file.size > STREAM_THRESHOLD_BYTES) return undefined;
    try {
      const buf = await readFile(file.absPath);
      if (buf.subarray(0, 8000).includes(0)) return undefined; // binary
      let text = buf.toString('utf8');
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // strip BOM
      return { text, lines: new LineIndex(text) };
    } catch {
      this.diagnostic({
        level: 'warning',
        code: 'file-unreadable',
        params: {},
        file: file.relPath,
      });
      return undefined;
    }
  }

  async *lines(file: FileRecord): AsyncIterable<{ text: string; line: number }> {
    if (file.size <= STREAM_THRESHOLD_BYTES) {
      const t = await this.readText(file);
      if (!t) return;
      for (let i = 1; i <= t.lines.lineCount; i++)
        yield { text: t.lines.lineText(t.text, i), line: i };
      return;
    }
    try {
      if (await isBinaryFile(file.absPath)) return;
      yield* streamLines(file.absPath);
    } catch {
      this.diagnostic({
        level: 'warning',
        code: 'file-unreadable',
        params: {},
        file: file.relPath,
      });
    }
  }

  parseTs(file: FileRecord): Promise<ParsedTs | undefined> {
    if (!CODE_KINDS.includes(file.kind)) return Promise.resolve(undefined);
    let p = this.tsCache.get(file.relPath);
    if (!p) {
      p = this.readText(file).then((t) => {
        if (!t) return undefined;
        if (t.text.length / Math.max(1, t.lines.lineCount) > MAX_AVG_LINE_LENGTH_FOR_AST)
          return undefined;
        return parseTypeScript(file.relPath, t.text, file.kind);
      });
      this.tsCache.set(file.relPath, p);
    }
    return p;
  }

  parseSql(file: FileRecord): Promise<ParsedSql | undefined> {
    if (file.kind !== 'sql') return Promise.resolve(undefined);
    let p = this.sqlCache.get(file.relPath);
    if (!p) {
      p = this.readText(file).then((t) => (t ? parseSql(t.text) : undefined));
      this.sqlCache.set(file.relPath, p);
    }
    return p;
  }

  diagnostic(d: Diagnostic): void {
    this.diags.push(d);
  }
}
