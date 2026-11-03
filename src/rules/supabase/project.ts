import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { FileRecord } from '../../core/discovery/walker.ts';
import type { RuleContext } from '../../core/engine/rule.ts';
import type { SourceLocation } from '../../core/findings/finding.ts';
import type { Confidence } from '../../core/findings/severity.ts';
import { scrubText, type Redacted } from '../../core/redaction/redact.ts';
import {
  applyMigration,
  newModel,
  type Loc,
  type SchemaModel,
  type TableState,
} from './schema-model.ts';

export const DEFAULT_EXPOSED_SCHEMAS = ['public', 'graphql_public'] as const;

export const SUPABASE_REFERENCES = [
  'https://supabase.com/docs/guides/database/postgres/row-level-security',
  'https://supabase.com/docs/guides/database/database-advisors',
  'https://www.postgresql.org/docs/current/ddl-rowsecurity.html',
] as const;

export interface SupabaseProject {
  /** posix dir of the migrations, relative to the scan root */
  readonly migrationsDir: string;
  readonly model: SchemaModel;
  readonly exposedSchemas: ReadonlySet<string>;
}

const cache = new WeakMap<RuleContext, Promise<SupabaseProject[]>>();

/**
 * Every Supabase project in the scan (monorepos can hold several), each with its
 * migrations replayed in filename order. Memoised per scan; diagnostics are emitted once.
 */
export function supabaseProjects(ctx: RuleContext): Promise<SupabaseProject[]> {
  let p = cache.get(ctx);
  if (!p) {
    p = load(ctx);
    cache.set(ctx, p);
  }
  return p;
}

/** Supabase timestamped migrations sort correctly by name; numeric collation handles `1_x` vs `10_x`. */
export function compareMigrationNames(a: string, b: string): number {
  return path.posix.basename(a).localeCompare(path.posix.basename(b), 'en', { numeric: true });
}

async function load(ctx: RuleContext): Promise<SupabaseProject[]> {
  const configured = ctx.settings.supabase.migrationsDirs?.map((d) => d.replace(/\/+$/, ''));
  const sqlFiles = ctx.files({ kinds: ['sql'] });
  const byDir = new Map<string, FileRecord[]>();
  for (const f of sqlFiles) {
    const dir = path.posix.dirname(f.relPath);
    const isMigrationDir = configured
      ? configured.includes(dir)
      : /(?:^|\/)supabase\/migrations$/.test(dir);
    if (!isMigrationDir) continue;
    const list = byDir.get(dir) ?? [];
    list.push(f);
    byDir.set(dir, list);
  }

  if (byDir.size === 0) {
    if (await usesSupabase(ctx)) {
      ctx.diagnostic({
        level: 'warning',
        code: 'no-migrations',
        params: { where: (configured ?? ['**/supabase/migrations']).join(', ') },
      });
    }
    return [];
  }

  const projects: SupabaseProject[] = [];
  for (const [dir, files] of [...byDir.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const model = newModel();
    for (const f of [...files].sort((a, b) => compareMigrationNames(a.relPath, b.relPath))) {
      const parsed = await ctx.parseSql(f);
      if (!parsed) continue;
      const text = await ctx.readText(f);
      for (const failure of parsed.failures) {
        ctx.diagnostic({
          level: 'warning',
          code: 'parse-failed',
          params: { error: failure.message.slice(0, 160) },
          file: f.relPath,
          line: text ? text.lines.position(failure.start).line : 1,
        });
      }
      const before = model.uncertainties.length;
      applyMigration(model, {
        file: f.relPath,
        statements: parsed.statements,
        failures: parsed.failures,
      });
      for (const u of model.uncertainties.slice(before)) {
        if (u.reason !== 'dynamic-sql') continue; // parse failures were reported above
        ctx.diagnostic({
          level: 'warning',
          code: 'dynamic-sql',
          params: { tables: u.tables.length > 0 ? u.tables.join(', ') : '?' },
          file: f.relPath,
          line: text ? text.lines.position(u.loc.start).line : 1,
        });
      }
    }
    projects.push({ migrationsDir: dir, model, exposedSchemas: await exposedSchemas(ctx, dir) });
  }
  return projects;
}

async function exposedSchemas(
  ctx: RuleContext,
  migrationsDir: string,
): Promise<ReadonlySet<string>> {
  const fromSettings = ctx.settings.supabase.exposedSchemas;
  if (fromSettings) return new Set(fromSettings);
  const configFile = ctx.file(path.posix.join(path.posix.dirname(migrationsDir), 'config.toml'));
  const t = configFile ? await ctx.readText(configFile) : undefined;
  if (t) {
    try {
      const doc = parseToml(t.text) as { api?: { schemas?: unknown } };
      const schemas = doc.api?.schemas;
      if (Array.isArray(schemas) && schemas.every((s) => typeof s === 'string'))
        return new Set(schemas);
    } catch {
      // Malformed config.toml: fall back to Supabase's defaults.
    }
  }
  return new Set(DEFAULT_EXPOSED_SCHEMAS);
}

async function usesSupabase(ctx: RuleContext): Promise<boolean> {
  if (ctx.files({ path: (p) => /(?:^|\/)supabase\/config\.toml$/.test(p) }).length > 0) return true;
  for (const f of ctx.files({
    kinds: ['json'],
    path: (p) => path.posix.basename(p) === 'package.json',
  })) {
    const t = await ctx.readText(f);
    if (t && /"@supabase\/[a-z-]+"\s*:|"supabase"\s*:/.test(t.text)) return true;
  }
  return false;
}

export interface Located {
  readonly location: SourceLocation;
  readonly evidence: Redacted;
}

/** Turn a statement location into a finding location plus a short, scrubbed SQL excerpt. */
export async function locate(ctx: RuleContext, loc: Loc): Promise<Located> {
  const f = ctx.file(loc.file);
  const t = f ? await ctx.readText(f) : undefined;
  const pos = t ? t.lines.position(loc.start) : { line: 1, column: 1 };
  const excerpt = loc.text.replace(/\s+/g, ' ').trim();
  return {
    location: { file: loc.file, line: pos.line, column: pos.column },
    evidence: scrubText(excerpt, { maxLength: 160 }),
  };
}

export function qualifiedName(t: { schema: string; name: string }): string {
  return `${t.schema}.${t.name}`;
}

/** The API roles cannot reach this table at all (REVOKE ALL from anon and authenticated). */
export function isRevokedFromApi(t: { revoked: ReadonlySet<string> }): boolean {
  return t.revoked.has('anon') && t.revoked.has('authenticated');
}

export function isUncertain(model: SchemaModel, t: TableState): boolean {
  return t.uncertain || model.globallyUncertain;
}

export function confidenceFor(model: SchemaModel, t: TableState, c: Confidence): Confidence {
  return isUncertain(model, t) ? 'low' : c;
}

/** Table names that are almost always meant to be world-readable reference data. */
export const PUBLIC_LOOKUP_TABLE =
  /(?:^|_)(?:countries|country|currencies|currency|languages|locales|timezones|categories|category|tags|tag|plans|plan|pricing|prices|features|faqs|faq|regions|states|cities|units|testimonials|changelog|public)(?:$|_)/i;
/** Table names that usually hold personal, financial or private data. */
export const SENSITIVE_TABLE =
  /(?:^|_)(?:profiles?|users?|accounts?|customers?|members?|orders?|payments?|invoices?|subscriptions?|messages?|chats?|conversations?|transactions?|addresses|emails?|tokens?|secrets?|keys|credentials|sessions?|notes?|documents?|files|private|billing|bank|medical|health|admins?|employees?|salaries|contacts?)(?:$|_)/i;
/** Write-only intake tables where anonymous INSERT is a common, deliberate design. */
export const INTAKE_TABLE =
  /(?:waitlist|newsletter|subscribers|contact|feedback|leads|signups|inquiries|enquiries)/i;
