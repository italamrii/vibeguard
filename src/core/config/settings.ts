import { DEFAULT_BUILD_OUTPUT_DIRS } from '../discovery/file-kind.ts';
import type { Confidence, Severity } from '../findings/severity.ts';
import type { ConfigFile, RuleSetting } from './schema.ts';

/** Fully-resolved settings after merging defaults, config file and CLI flags. */
export interface Settings {
  readonly ignore: readonly string[];
  readonly rules: Readonly<Record<string, RuleSetting>>;
  readonly failOn: Severity | 'none';
  readonly minConfidence: Confidence;
  readonly discovery: {
    readonly skipBuildOutput: boolean;
    readonly buildOutputDirs: readonly string[];
  };
  readonly supabase: {
    readonly migrationsDirs: readonly string[];
    /** `undefined` means "derive from supabase/config.toml, else ['public']". */
    readonly exposedSchemas: readonly string[] | undefined;
  };
  readonly endpoints: {
    readonly authFunctions: readonly string[];
    readonly rateLimitFunctions: readonly string[];
  };
}

export const DEFAULT_SETTINGS: Settings = {
  ignore: [],
  rules: {},
  failOn: 'high',
  minConfidence: 'low',
  discovery: { skipBuildOutput: true, buildOutputDirs: DEFAULT_BUILD_OUTPUT_DIRS },
  supabase: { migrationsDirs: ['supabase/migrations'], exposedSchemas: undefined },
  endpoints: { authFunctions: [], rateLimitFunctions: [] },
};

export interface CliOverrides {
  readonly failOn?: Severity | 'none';
  readonly minConfidence?: Confidence;
}

export function resolveSettings(file: ConfigFile | undefined, cli: CliOverrides = {}): Settings {
  const d = DEFAULT_SETTINGS;
  return {
    ignore: file?.ignore ?? d.ignore,
    rules: file?.rules ?? d.rules,
    failOn: cli.failOn ?? file?.failOn ?? d.failOn,
    minConfidence: cli.minConfidence ?? file?.minConfidence ?? d.minConfidence,
    discovery: {
      skipBuildOutput: file?.discovery?.skipBuildOutput ?? d.discovery.skipBuildOutput,
      buildOutputDirs: file?.discovery?.buildOutputDirs ?? d.discovery.buildOutputDirs,
    },
    supabase: {
      migrationsDirs: file?.supabase?.migrationsDirs ?? d.supabase.migrationsDirs,
      exposedSchemas: file?.supabase?.exposedSchemas ?? d.supabase.exposedSchemas,
    },
    endpoints: {
      authFunctions: file?.endpoints?.authFunctions ?? d.endpoints.authFunctions,
      rateLimitFunctions: file?.endpoints?.rateLimitFunctions ?? d.endpoints.rateLimitFunctions,
    },
  };
}

export function isRuleEnabled(settings: Settings, ruleId: string): boolean {
  const s = settings.rules[ruleId];
  if (s === undefined || s === 'on') return true;
  if (s === 'off') return false;
  return s.enabled ?? true;
}

export function severityOverride(settings: Settings, ruleId: string): Severity | undefined {
  const s = settings.rules[ruleId];
  return typeof s === 'object' ? s.severity : undefined;
}

/** Directory names the walker should skip as build output under these settings. */
export function effectiveBuildOutputDirs(settings: Settings): readonly string[] {
  return settings.discovery.skipBuildOutput ? settings.discovery.buildOutputDirs : [];
}
