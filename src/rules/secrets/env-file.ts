export interface EnvAssignment {
  readonly name: string;
  readonly value: string;
  /** 1-based line of the assignment. */
  readonly line: number;
  /** 1-based column of the variable name. */
  readonly column: number;
  /** 1-based column where the value starts (after any opening quote). */
  readonly valueColumn: number;
}

const ASSIGNMENT = /^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

/**
 * Parse dotenv syntax: `KEY=value`, `export KEY=value`, single/double/back-quoted values,
 * trailing ` # comments` on unquoted values. Multi-line quoted values are reported on
 * their first line with the first line of content, which is enough to classify them.
 */
export function parseEnvLines(lines: readonly string[]): EnvAssignment[] {
  const out: EnvAssignment[] = [];
  lines.forEach((raw, i) => {
    const m = ASSIGNMENT.exec(raw);
    if (!m) return;
    const indent = m[1] ?? '';
    const exp = m[2] ?? '';
    const name = m[3] ?? '';
    const rest = m[4] ?? '';
    const restStart = raw.length - rest.length;
    let value: string;
    let offset = 0;
    const q = rest[0];
    if (q === '"' || q === "'" || q === '`') {
      const close = rest.indexOf(q, 1);
      value = close === -1 ? rest.slice(1) : rest.slice(1, close);
      offset = 1;
    } else {
      value = rest.replace(/\s+#.*$/, '').trim();
    }
    out.push({
      name,
      value,
      line: i + 1,
      column: indent.length + exp.length + 1,
      valueColumn: restStart + offset + 1,
    });
  });
  return out;
}
