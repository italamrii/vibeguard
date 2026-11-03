import { createHash } from 'node:crypto';
import type { RuleContext } from '../../core/engine/rule.ts';
import type { FileRecord } from '../../core/discovery/walker.ts';
import type { Confidence } from '../../core/findings/severity.ts';
import { findSecrets, type SecretMatch } from './patterns.ts';

export const SECRETS_REFERENCES = [
  'https://cwe.mitre.org/data/definitions/798.html',
  'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
] as const;

/**
 * Should hardcoded-secret rules look at this file? A gitignored, untracked env file
 * (e.g. `.env.local`) is exactly where local secrets belong; flagging it would teach
 * users to ignore the tool. A *tracked* env file is in git history whether ignored or not.
 */
export function hardcodedScanApplies(f: FileRecord): boolean {
  return !(f.gitIgnored && f.gitTracked !== true);
}

const TEST_PATH =
  /(?:^|\/)(?:__tests__|__mocks__|tests?|spec|specs|e2e|cypress|playwright|mocks?|fixtures?|__fixtures__|testdata)\/|\.(?:test|spec|stories)\.[cm]?[jt]sx?$/i;

export function isTestPath(relPath: string): boolean {
  return TEST_PATH.test(relPath);
}

export function lowerConfidence(c: Confidence): Confidence {
  return c === 'high' ? 'medium' : 'low';
}

/**
 * Secrets in test code are usually fakes, but not always (real keys get pasted into
 * integration tests). We keep the finding and lower its confidence one step.
 */
export function confidenceForPath(c: Confidence, relPath: string): Confidence {
  return isTestPath(relPath) ? lowerConfidence(c) : c;
}

/** Hash used in fingerprints so the raw secret never enters any derived identifier. */
export function secretDigest(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 16);
}

export interface LocatedSecret extends SecretMatch {
  readonly line: number;
  readonly column: number;
  readonly endLine: number;
  readonly endColumn: number;
}

const cache = new WeakMap<RuleContext, Map<string, Promise<LocatedSecret[]>>>();

/**
 * Provider-secret matches for a file, memoised per scan so the provider-key,
 * high-entropy and client-exposed-env rules share one pass. Files over the streaming
 * threshold are scanned line by line.
 */
export function secretsInFile(ctx: RuleContext, file: FileRecord): Promise<LocatedSecret[]> {
  let perCtx = cache.get(ctx);
  if (!perCtx) {
    perCtx = new Map();
    cache.set(ctx, perCtx);
  }
  let p = perCtx.get(file.relPath);
  if (!p) {
    p = compute(ctx, file);
    perCtx.set(file.relPath, p);
  }
  return p;
}

async function compute(ctx: RuleContext, file: FileRecord): Promise<LocatedSecret[]> {
  const t = await ctx.readText(file);
  if (t) {
    return findSecrets(t.text).map((m) => {
      const start = t.lines.position(m.index);
      const end = t.lines.position(m.index + m.secret.length);
      return {
        ...m,
        line: start.line,
        column: start.column,
        endLine: end.line,
        endColumn: end.column,
      };
    });
  }
  const out: LocatedSecret[] = [];
  for await (const { text, line } of ctx.lines(file)) {
    for (const m of findSecrets(text)) {
      out.push({
        ...m,
        line,
        column: m.index + 1,
        endLine: line,
        endColumn: m.index + m.secret.length + 1,
      });
    }
  }
  return out;
}
