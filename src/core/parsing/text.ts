import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { createInterface } from 'node:readline';

/** Files at or below this size are read whole and cached; larger ones are streamed. */
export const STREAM_THRESHOLD_BYTES = 1024 * 1024;
const BINARY_SNIFF_BYTES = 8000;

/** Heuristic used by git: a NUL byte in the first 8000 bytes means binary. */
export async function isBinaryFile(absPath: string): Promise<boolean> {
  const fh = await open(absPath, 'r');
  try {
    const buf = Buffer.alloc(BINARY_SNIFF_BYTES);
    const { bytesRead } = await fh.read(buf, 0, BINARY_SNIFF_BYTES, 0);
    return buf.subarray(0, bytesRead).includes(0);
  } finally {
    await fh.close();
  }
}

/** Stream a file line by line (1-based line numbers) without loading it into memory. */
export async function* streamLines(
  absPath: string,
): AsyncGenerator<{ text: string; line: number }> {
  const rl = createInterface({
    input: createReadStream(absPath, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  let line = 0;
  for await (const text of rl) {
    line++;
    yield { text, line };
  }
}

/** Maps string offsets to 1-based line/column. */
export class LineIndex {
  private readonly starts: number[];

  constructor(text: string) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) starts.push(i + 1);
    }
    this.starts = starts;
  }

  get lineCount(): number {
    return this.starts.length;
  }

  position(offset: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] ?? 0) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - (this.starts[lo] ?? 0) + 1 };
  }

  lineText(text: string, line: number): string {
    const start = this.starts[line - 1];
    if (start === undefined) return '';
    const next = this.starts[line];
    const end = next === undefined ? text.length : next - 1;
    return text.slice(start, end).replace(/\r$/, '');
  }
}
