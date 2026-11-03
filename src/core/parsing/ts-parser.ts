import ts from 'typescript';
import type { FileKind } from '../discovery/file-kind.ts';

/**
 * Parse a JS/TS file into a syntax tree. Parse-only: no Program, no type checker, no
 * module resolution, no reading of other files. See docs/adr/0001-parser-choice.md.
 *
 * The TypeScript parser is error-tolerant: it always returns a tree, recovering from
 * syntax errors. `parseErrorCount` lets callers lower confidence on badly broken files.
 */
export function parseTypeScript(fileName: string, text: string, kind: FileKind): ParsedTs {
  const scriptKind =
    kind === 'tsx'
      ? ts.ScriptKind.TSX
      : kind === 'jsx'
        ? ts.ScriptKind.JSX
        : kind === 'js'
          ? ts.ScriptKind.JS
          : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(
    fileName,
    text,
    { languageVersion: ts.ScriptTarget.Latest, jsDocParsingMode: ts.JSDocParsingMode.ParseNone },
    /* setParentNodes */ true,
    scriptKind,
  );
  return { sourceFile, parseErrorCount: countParseErrors(sourceFile) };
}

export interface ParsedTs {
  readonly sourceFile: ts.SourceFile;
  readonly parseErrorCount: number;
}

function countParseErrors(sf: ts.SourceFile): number {
  // `parseDiagnostics` is internal to the TypeScript API but has been stable since TS 2.x.
  // We read it defensively and treat absence as "no errors".
  const diags: unknown = (sf as unknown as { parseDiagnostics?: unknown }).parseDiagnostics;
  return Array.isArray(diags) ? diags.length : 0;
}

/** 1-based position of a node's start (excluding leading trivia). */
export function nodePosition(
  sf: ts.SourceFile,
  node: ts.Node,
): { line: number; column: number; endLine: number; endColumn: number } {
  const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const end = sf.getLineAndCharacterOfPosition(node.getEnd());
  return {
    line: start.line + 1,
    column: start.character + 1,
    endLine: end.line + 1,
    endColumn: end.character + 1,
  };
}
