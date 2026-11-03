import {
  effectiveBuildOutputDirs,
  isRuleEnabled,
  severityOverride,
  type Settings,
} from '../config/settings.ts';
import { discoverFiles, type FileRecord } from '../discovery/walker.ts';
import type { Diagnostic, Finding, FindingInput } from '../findings/finding.ts';
import { fingerprint } from '../findings/fingerprint.ts';
import { meetsConfidence, severityRank } from '../findings/severity.ts';
import { scrubText } from '../redaction/redact.ts';
import {
  findSuppression,
  parseSuppressions,
  SUPPRESSION_TOKEN,
  type ParsedSuppressions,
} from '../suppression/suppression.ts';
import type { MessageParams } from '../../i18n/locale.ts';
import { ProjectContext } from './context.ts';
import { RULE_ID_PATTERN, type Rule, type RuleMeta } from './rule.ts';

export interface ScanOptions {
  readonly root: string;
  readonly settings: Settings;
  readonly rules: readonly Rule[];
}

export interface ScanResult {
  /** Absolute scan root. Reporters must not print it (it leaks local usernames); paths are relative. */
  readonly root: string;
  readonly findings: readonly Finding[];
  /** Findings dropped by `minConfidence` — counted so reports can say they exist. */
  readonly belowConfidenceThreshold: number;
  readonly diagnostics: readonly Diagnostic[];
  readonly rules: readonly RuleMeta[];
  readonly filesScanned: number;
  readonly durationMs: number;
  /** False when any `error` diagnostic occurred: the result must not be treated as clean. */
  readonly complete: boolean;
}

export class RuleRegistryError extends Error {
  override name = 'RuleRegistryError';
}

/** Validate rule metadata once, before scanning. A malformed rule is a programming error. */
export function validateRules(rules: readonly Rule[]): void {
  const seen = new Set<string>();
  for (const r of rules) {
    const { id, family } = r.meta;
    if (!RULE_ID_PATTERN.test(id)) throw new RuleRegistryError(`Invalid rule id "${id}"`);
    if (!id.startsWith(`${family}/`))
      throw new RuleRegistryError(`Rule "${id}" must start with its family "${family}/"`);
    if (seen.has(id)) throw new RuleRegistryError(`Duplicate rule id "${id}"`);
    if (Object.keys(r.meta.messages).length === 0)
      throw new RuleRegistryError(`Rule "${id}" has no messages`);
    seen.add(id);
  }
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const started = performance.now();
  validateRules(opts.rules);
  const { settings } = opts;

  const discovery = await discoverFiles({
    root: opts.root,
    ignorePatterns: settings.ignore,
    buildOutputDirs: effectiveBuildOutputDirs(settings),
  });
  const ctx = new ProjectContext(discovery.root, settings, discovery.files);
  const enabled = opts.rules.filter((r) => isRuleEnabled(settings, r.meta.id));

  // Rules run concurrently over shared caches. Each is isolated: a crash becomes an error
  // diagnostic (and an incomplete scan), never a silently missing result.
  const perRule = await Promise.all(
    enabled.map(async (rule) => {
      try {
        const out = await rule.detect(ctx);
        return { rule, out };
      } catch (err) {
        ctx.diagnostic({
          level: 'error',
          code: 'rule-crashed',
          params: { rule: rule.meta.id, error: errorSummary(err) },
        });
        return { rule, out: [] as readonly FindingInput[] };
      }
    }),
  );

  const raw: Finding[] = [];
  for (const { rule, out } of perRule) raw.push(...materialize(rule, out, settings, ctx));

  const knownIds = new Set(opts.rules.map((r) => r.meta.id));
  const suppressed = await applySuppressions(raw, ctx, knownIds);

  const visible = suppressed.filter((f) => meetsConfidence(f.confidence, settings.minConfidence));
  const belowConfidenceThreshold = suppressed.length - visible.length;
  visible.sort(compareFindings);

  const diagnostics = [...discovery.diagnostics, ...ctx.diagnostics];
  return {
    root: discovery.root,
    findings: visible,
    belowConfidenceThreshold,
    diagnostics,
    rules: enabled.map((r) => r.meta),
    filesScanned: discovery.files.length,
    durationMs: Math.round(performance.now() - started),
    complete: !diagnostics.some((d) => d.level === 'error'),
  };
}

function materialize(
  rule: Rule,
  inputs: readonly FindingInput[],
  settings: Settings,
  ctx: ProjectContext,
): Finding[] {
  const meta = rule.meta;
  const override = severityOverride(settings, meta.id);
  const occurrences = new Map<string, number>();
  const seenFingerprints = new Set<string>();
  const out: Finding[] = [];
  for (const input of inputs) {
    if (!(input.messageId in meta.messages)) {
      ctx.diagnostic({
        level: 'error',
        code: 'rule-crashed',
        params: { rule: meta.id, error: `unknown messageId "${input.messageId}"` },
      });
      continue;
    }
    const file = input.location.file;
    const key = input.fingerprintKey ?? `${input.messageId}\0${input.evidence}`;
    const occKey = `${file}\0${key}`;
    const n = occurrences.get(occKey) ?? 0;
    occurrences.set(occKey, n + 1);
    const fp = fingerprint(meta.id, file, key, n);
    if (seenFingerprints.has(fp)) continue;
    seenFingerprints.add(fp);
    out.push({
      ruleId: meta.id,
      severity: override ?? input.severity ?? meta.defaultSeverity,
      confidence: input.confidence,
      location: input.location,
      messageId: input.messageId,
      params: scrubParams(input.params ?? {}),
      evidence: input.evidence,
      cwe: meta.cwe,
      references: meta.references,
      fingerprint: fp,
    });
  }
  return out;
}

async function applySuppressions(
  findings: readonly Finding[],
  ctx: ProjectContext,
  knownIds: ReadonlySet<string>,
): Promise<Finding[]> {
  // Parse every file that mentions the token, not only files with findings, so that
  // stale suppressions and malformed directives are reported too.
  const parsedByFile = new Map<string, ParsedSuppressions>();
  await Promise.all(
    ctx.files().map(async (f: FileRecord) => {
      const t = await ctx.readText(f);
      if (!t || !t.text.includes(SUPPRESSION_TOKEN)) return;
      const lines = t.text.split(/\r?\n/);
      parsedByFile.set(f.relPath, parseSuppressions(lines, knownIds));
    }),
  );

  const used = new Set<string>(); // `${file}:${line}`
  const result = findings.map((f): Finding => {
    const parsed = parsedByFile.get(f.location.file);
    if (!parsed) return f;
    const d = findSuppression(parsed, f.ruleId, f.location.line);
    if (!d) return f;
    used.add(`${f.location.file}:${d.line}`);
    return { ...f, suppression: { reason: d.reason, line: d.line } };
  });

  for (const [file, parsed] of [...parsedByFile.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    for (const inv of parsed.invalid) {
      ctx.diagnostic({
        level: 'warning',
        code: 'invalid-suppression',
        params: { problem: inv.problem, detail: inv.detail },
        file,
        line: inv.line,
      });
    }
    for (const d of parsed.directives) {
      if (!used.has(`${file}:${d.line}`)) {
        ctx.diagnostic({
          level: 'warning',
          code: 'unused-suppression',
          params: { rules: d.ruleIds.join(', ') },
          file,
          line: d.line,
        });
      }
    }
  }
  return result;
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    (a.location.file < b.location.file ? -1 : a.location.file > b.location.file ? 1 : 0) ||
    a.location.line - b.location.line ||
    a.location.column - b.location.column ||
    (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0)
  );
}

/**
 * Params are interpolated into human-readable messages. They are meant for identifiers
 * (table names, env var names), never secrets, but we scrub them anyway: a rule bug must
 * not be able to print a credential.
 */
function scrubParams(params: MessageParams): MessageParams {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(params))
    out[k] = typeof v === 'string' ? scrubText(v, { maxLength: 200 }) : v;
  return out;
}

function errorSummary(err: unknown): string {
  const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  // Parser/runtime errors can echo file content, which may include a secret.
  return scrubText(msg, { maxLength: 300 });
}
