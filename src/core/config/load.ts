import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { configFileSchema, type ConfigFile } from './schema.ts';

export const CONFIG_FILE_NAMES = ['.vibeguard.yml', '.vibeguard.yaml'] as const;
const MAX_CONFIG_BYTES = 256 * 1024;

export class ConfigError extends Error {
  readonly file: string;

  constructor(message: string, file: string) {
    super(message);
    this.name = 'ConfigError';
    this.file = file;
  }
}

export interface LoadedConfig {
  readonly config: ConfigFile | undefined;
  /** Path of the file that was loaded, if any. */
  readonly source: string | undefined;
}

/**
 * Load config from an explicit path, or from the scan root. Parsing is data-only: the
 * YAML library is used with its core schema (no custom tags), and nothing in the config
 * can cause code to be loaded or executed.
 */
export async function loadConfig(root: string, explicitPath?: string): Promise<LoadedConfig> {
  const candidates = explicitPath
    ? [path.resolve(explicitPath)]
    : CONFIG_FILE_NAMES.map((n) => path.join(root, n));

  for (const file of candidates) {
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch (err) {
      if (explicitPath) throw new ConfigError(`Cannot read config file: ${describe(err)}`, file);
      continue;
    }
    if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) {
      throw new ConfigError('Config file is too large (limit 256 KiB).', file);
    }
    let raw: unknown;
    try {
      raw = parseYaml(text, { schema: 'core', maxAliasCount: 50 });
    } catch (err) {
      throw new ConfigError(`Invalid YAML: ${describe(err)}`, file);
    }
    const parsed = configFileSchema.safeParse(raw ?? {});
    if (!parsed.success) {
      const issues = parsed.error.issues
        .map((i) => `  - ${i.path.length > 0 ? i.path.join('.') : '(root)'}: ${i.message}`)
        .join('\n');
      throw new ConfigError(`Invalid config:\n${issues}`, file);
    }
    return { config: parsed.data, source: file };
  }
  return { config: undefined, source: undefined };
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
