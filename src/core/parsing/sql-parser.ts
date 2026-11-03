import { loadModule, parseSync, scanSync, type Node } from 'libpg-query';

/**
 * PostgreSQL parsing via libpg-query: the real Postgres parser (the C source of the
 * server's grammar) compiled to WebAssembly. No native compilation; see ADR-0002.
 *
 * Robustness contract (never crash, never silently drop):
 *  1. Parse the whole file.
 *  2. If that fails, split it into statements with the Postgres *lexer* (which still
 *     works on syntactically invalid input), and parse each statement on its own.
 *  3. Statements that still fail are returned as `failures` with their text and
 *     position, so callers can report them and mark what they touch as unknown.
 * If even the lexer fails (e.g. an unterminated quote), the whole file is one failure.
 */

export interface SqlStatement {
  readonly node: Node;
  /** Character offset of the statement's first token (comments/whitespace skipped). */
  readonly start: number;
  /** Character offset just past the statement (excluding the semicolon). */
  readonly end: number;
  readonly text: string;
}

export interface SqlParseFailure {
  readonly start: number;
  readonly end: number;
  readonly text: string;
  readonly message: string;
}

export interface ParsedSql {
  readonly statements: readonly SqlStatement[];
  readonly failures: readonly SqlParseFailure[];
}

let ready: Promise<void> | undefined;

/** Load the WASM module once per process. */
export function initSqlParser(): Promise<void> {
  ready ??= loadModule();
  return ready;
}

/** Converts UTF-8 byte offsets (what Postgres reports) to JS string offsets. */
class OffsetMap {
  private readonly ascii: boolean;
  private readonly buf: Buffer;
  constructor(text: string) {
    this.buf = Buffer.from(text, 'utf8');
    this.ascii = this.buf.length === text.length;
  }
  toChar(byteOffset: number): number {
    return this.ascii ? byteOffset : this.buf.subarray(0, byteOffset).toString('utf8').length;
  }
  get byteLength(): number {
    return this.buf.length;
  }
}

/** Skip whitespace and SQL comments (`--`, nested `/* *\/`) starting at `i`. */
export function skipTrivia(text: string, i: number, end = text.length): number {
  let p = i;
  while (p < end) {
    const c = text[p];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') {
      p++;
    } else if (c === '-' && text[p + 1] === '-') {
      const nl = text.indexOf('\n', p);
      p = nl === -1 ? end : nl + 1;
    } else if (c === '/' && text[p + 1] === '*') {
      let depth = 1;
      p += 2;
      while (p < end && depth > 0) {
        if (text[p] === '/' && text[p + 1] === '*') {
          depth++;
          p += 2;
        } else if (text[p] === '*' && text[p + 1] === '/') {
          depth--;
          p += 2;
        } else p++;
      }
    } else break;
  }
  return Math.min(p, end);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function parseChunk(text: string, base: number): { ok: SqlStatement[] } | { error: string } {
  try {
    const result = parseSync(text);
    const map = new OffsetMap(text);
    const out: SqlStatement[] = [];
    for (const raw of result.stmts ?? []) {
      if (!raw.stmt) continue;
      const startByte = raw.stmt_location ?? 0;
      const endByte =
        raw.stmt_len === undefined || raw.stmt_len === 0
          ? map.byteLength
          : startByte + raw.stmt_len;
      const rawStart = map.toChar(startByte);
      const end = map.toChar(endByte);
      const start = skipTrivia(text, rawStart, end);
      out.push({
        node: raw.stmt,
        start: base + start,
        end: base + end,
        text: text.slice(start, end),
      });
    }
    return { ok: out };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

/** Statement boundaries from the lexer: [start, end) character ranges, semicolons excluded. */
function splitStatements(text: string): [number, number][] {
  const map = new OffsetMap(text);
  const tokens = scanSync(text).tokens;
  const ranges: [number, number][] = [];
  let from = 0;
  for (const t of tokens) {
    if (t.text !== ';') continue;
    const semi = map.toChar(t.start);
    ranges.push([from, semi]);
    from = map.toChar(t.end);
  }
  ranges.push([from, text.length]);
  return ranges.filter(([s, e]) => skipTrivia(text, s, e) < e);
}

export async function parseSql(text: string): Promise<ParsedSql> {
  await initSqlParser();
  const whole = parseChunk(text, 0);
  if ('ok' in whole) return { statements: whole.ok, failures: [] };

  let ranges: [number, number][];
  try {
    ranges = splitStatements(text);
  } catch (err) {
    const start = skipTrivia(text, 0);
    return {
      statements: [],
      failures: [{ start, end: text.length, text: text.slice(start), message: errorMessage(err) }],
    };
  }
  const statements: SqlStatement[] = [];
  const failures: SqlParseFailure[] = [];
  for (const [s, e] of ranges) {
    const chunk = text.slice(s, e);
    const r = parseChunk(chunk, s);
    if ('ok' in r) statements.push(...r.ok);
    else {
      const start = skipTrivia(text, s, e);
      failures.push({ start, end: e, text: text.slice(start, e), message: r.error });
    }
  }
  return { statements, failures };
}
