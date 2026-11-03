import { gzipSync } from 'node:zlib';

/**
 * Checks for the constraints GitHub code scanning applies to uploaded SARIF, beyond the
 * SARIF schema itself. Values are from GitHub's "SARIF support for code scanning"
 * documentation at the time of writing; re-check them before each release
 * (docs/release-checklist.md).
 */
export const GITHUB_SARIF_LIMITS = {
  maxGzipBytes: 10 * 1024 * 1024,
  maxRunsPerFile: 20,
  maxResultsPerRun: 25_000,
  maxRulesPerRun: 25_000,
  maxLocationsPerResult: 1_000,
  maxTagsPerRule: 20,
} as const;

type Json = Record<string, unknown>;

function obj(v: unknown): Json | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Json) : undefined;
}

function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** Returns a list of problems; empty when the document fits GitHub's expectations. */
export function checkGitHubSarif(text: string): string[] {
  const problems: string[] = [];
  const gz = gzipSync(Buffer.from(text, 'utf8')).length;
  if (gz > GITHUB_SARIF_LIMITS.maxGzipBytes)
    problems.push(`gzip size ${gz} exceeds ${GITHUB_SARIF_LIMITS.maxGzipBytes}`);
  let doc: Json | undefined;
  try {
    doc = obj(JSON.parse(text));
  } catch {
    return ['not valid JSON'];
  }
  if (!doc) return ['top level is not an object'];
  if (doc['version'] !== '2.1.0') problems.push('version must be "2.1.0"');
  const runs = arr(doc['runs']);
  if (runs.length === 0) problems.push('no runs');
  if (runs.length > GITHUB_SARIF_LIMITS.maxRunsPerFile)
    problems.push(`more than ${GITHUB_SARIF_LIMITS.maxRunsPerFile} runs`);

  runs.forEach((runV, ri) => {
    const run = obj(runV) ?? {};
    const driver = obj(obj(run['tool'])?.['driver']);
    if (typeof driver?.['name'] !== 'string' || driver['name'] === '')
      problems.push(`run ${ri}: tool.driver.name missing`);
    const rules = arr(driver?.['rules']);
    if (rules.length > GITHUB_SARIF_LIMITS.maxRulesPerRun)
      problems.push(`run ${ri}: too many rules`);
    const ids = new Set<string>();
    rules.forEach((rv, i) => {
      const r = obj(rv) ?? {};
      const id = r['id'];
      if (typeof id !== 'string') problems.push(`run ${ri} rule ${i}: missing id`);
      else if (ids.has(id)) problems.push(`run ${ri}: duplicate rule id ${id}`);
      else ids.add(id);
      const props = obj(r['properties']) ?? {};
      if (arr(props['tags']).length > GITHUB_SARIF_LIMITS.maxTagsPerRule)
        problems.push(`rule ${String(id)}: more than 20 tags`);
      const sev = props['security-severity'];
      const n = typeof sev === 'string' ? Number(sev) : NaN;
      if (!(n > 0 && n <= 10))
        problems.push(`rule ${String(id)}: security-severity must be a numeric string in (0, 10]`);
      if (typeof r['helpUri'] !== 'string') problems.push(`rule ${String(id)}: helpUri missing`);
      if (typeof obj(r['help'])?.['text'] !== 'string')
        problems.push(`rule ${String(id)}: help.text missing`);
    });

    const results = arr(run['results']);
    if (results.length > GITHUB_SARIF_LIMITS.maxResultsPerRun)
      problems.push(`run ${ri}: more than 25,000 results`);
    results.forEach((resV, i) => {
      const res = obj(resV) ?? {};
      const where = `run ${ri} result ${i}`;
      if (typeof res['ruleId'] !== 'string' || !ids.has(res['ruleId']))
        problems.push(`${where}: ruleId not described in tool.driver.rules`);
      if (typeof obj(res['message'])?.['text'] !== 'string')
        problems.push(`${where}: message.text missing`);
      if (!['error', 'warning', 'note', 'none'].includes(String(res['level'])))
        problems.push(`${where}: invalid level`);
      const fp = obj(res['partialFingerprints']);
      if (!fp || Object.keys(fp).length === 0)
        problems.push(`${where}: partialFingerprints missing (alerts would churn)`);
      const locs = arr(res['locations']);
      if (locs.length === 0) problems.push(`${where}: no locations`);
      if (locs.length > GITHUB_SARIF_LIMITS.maxLocationsPerResult)
        problems.push(`${where}: too many locations`);
      for (const lv of locs) {
        const pl = obj(obj(lv)?.['physicalLocation']);
        const uri = obj(pl?.['artifactLocation'])?.['uri'];
        if (typeof uri !== 'string' || uri === '')
          problems.push(`${where}: artifactLocation.uri missing`);
        else if (
          /^[a-z][a-z0-9+.-]*:/i.test(uri) ||
          uri.startsWith('/') ||
          uri.split('/').includes('..')
        ) {
          problems.push(`${where}: uri must be relative to the repository root: ${uri}`);
        }
        const line = obj(pl?.['region'])?.['startLine'];
        if (typeof line !== 'number' || line < 1)
          problems.push(`${where}: region.startLine must be >= 1`);
      }
    });
  });
  return problems;
}
