import { readFileSync } from 'node:fs';
import { realpath, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Command, CommanderError, InvalidArgumentError, Option } from 'commander';
import { ConfigError, loadConfig } from '../core/config/load.ts';
import { resolveSettings, type Settings } from '../core/config/settings.ts';
import { scan, type ScanResult } from '../core/engine/engine.ts';
import type { Rule } from '../core/engine/rule.ts';
import {
  CONFIDENCES,
  isConfidence,
  isSeverity,
  SEVERITIES,
  type Confidence,
  type Severity,
} from '../core/findings/severity.ts';
import { isLocale, LOCALES, type Locale } from '../i18n/locale.ts';
import { UI } from '../i18n/ui.ts';
import { REPORT_FORMATS, REPORTERS } from '../reporters/index.ts';
import { ALL_RULES } from '../rules/index.ts';
import { ExitCode, exitCodeFor } from './exit-codes.ts';

export interface CliIO {
  readonly stdout: (s: string) => void;
  readonly stderr: (s: string) => void;
  readonly stdoutIsTTY: boolean;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly cwd: string;
}

export interface RunOptions {
  /** Injected for tests; defaults to the real registry. */
  readonly rules?: readonly Rule[];
}

const HELP_NOTICE = `
${UI.en.ownCodeNotice}
VibeGuard is read-only and offline: it never modifies the scanned project and never
sends code or findings anywhere.`;

export function toolVersion(): string {
  // dist/cli/run.js and src/cli/run.ts are both two levels below package.json.
  const pkgUrl = new URL('../../package.json', import.meta.url);
  const pkg = JSON.parse(readFileSync(pkgUrl, 'utf8')) as { version?: unknown };
  return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
}

function parseSeverityOrNone(v: string): Severity | 'none' {
  if (v === 'none' || isSeverity(v)) return v;
  throw new InvalidArgumentError(`expected one of: ${[...SEVERITIES, 'none'].join(', ')}`);
}
function parseConfidence(v: string): Confidence {
  if (isConfidence(v)) return v;
  throw new InvalidArgumentError(`expected one of: ${CONFIDENCES.join(', ')}`);
}
function parseLocale(v: string): Locale {
  if (isLocale(v)) return v;
  throw new InvalidArgumentError(`expected one of: ${LOCALES.join(', ')}`);
}
function parseFormat(v: string): string {
  if (REPORTERS.has(v)) return v;
  throw new InvalidArgumentError(`expected one of: ${REPORT_FORMATS.join(', ')}`);
}

interface ScanFlags {
  format: string;
  output?: string;
  lang: Locale;
  failOn?: Severity | 'none';
  minConfidence?: Confidence;
  config?: string;
  color?: boolean;
}

/** Entry point shared by the binary and the tests. Returns the process exit code. */
export async function run(
  argv: readonly string[],
  io: CliIO,
  runOpts: RunOptions = {},
): Promise<number> {
  const rules = runOpts.rules ?? ALL_RULES;
  let exitCode: number = ExitCode.Ok;

  const program = new Command()
    .name('vibeguard')
    .description(
      'Static, local, read-only security scanner for AI-generated web apps (Next.js, React, Node, Supabase, Firebase).',
    )
    .version(toolVersion(), '-v, --version')
    .addHelpText('after', HELP_NOTICE)
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr })
    .showHelpAfterError('(run with --help for usage)');

  program
    .command('scan')
    .description('Scan a project directory you own or are authorized to assess.')
    .argument('[path]', 'project directory', '.')
    .addOption(
      new Option('-f, --format <format>', `output format: ${REPORT_FORMATS.join(', ')}`)
        .default('terminal')
        .argParser(parseFormat),
    )
    .option(
      '-o, --output <file>',
      'write the report to a file (must be outside the scanned project)',
    )
    .addOption(
      new Option('-l, --lang <lang>', `report language: ${LOCALES.join(', ')}`)
        .default('en')
        .argParser(parseLocale),
    )
    .addOption(
      new Option(
        '--fail-on <severity>',
        'exit 1 when a finding at or above this severity exists: critical, high, medium, low, none',
      ).argParser(parseSeverityOrNone),
    )
    .addOption(
      new Option(
        '--min-confidence <level>',
        'hide findings below this confidence: high, medium, low',
      ).argParser(parseConfidence),
    )
    .option(
      '-c, --config <file>',
      'config file (default: <path>/.vibeguard.yml). In CI, prefer a trusted path outside the scanned code',
    )
    .option('--no-color', 'disable ANSI colours')
    .addHelpText('after', HELP_NOTICE)
    .action(async (target: string, flags: ScanFlags) => {
      exitCode = await scanCommand(target, flags, io, rules);
    });

  program
    .command('rules')
    .description('List the available rules.')
    .addOption(
      new Option('-l, --lang <lang>', `language: ${LOCALES.join(', ')}`)
        .default('en')
        .argParser(parseLocale),
    )
    .action((flags: { lang: Locale }) => {
      for (const r of rules) {
        io.stdout(
          `${r.meta.id.padEnd(40)} ${r.meta.defaultSeverity.padEnd(9)} ${r.meta.docs.title[flags.lang]}\n`,
        );
      }
    });

  try {
    await program.parseAsync([...argv], { from: 'user' });
  } catch (err) {
    if (err instanceof CommanderError) {
      // --help and --version exit through here with exitCode 0.
      return err.exitCode === 0 ? ExitCode.Ok : ExitCode.UsageError;
    }
    throw err;
  }
  return exitCode;
}

async function scanCommand(
  target: string,
  flags: ScanFlags,
  io: CliIO,
  rules: readonly Rule[],
): Promise<number> {
  const root = path.resolve(io.cwd, target);
  try {
    if (!(await stat(root)).isDirectory()) {
      io.stderr(`vibeguard: not a directory: ${target}\n`);
      return ExitCode.UsageError;
    }
  } catch {
    io.stderr(`vibeguard: path not found: ${target}\n`);
    return ExitCode.UsageError;
  }

  let outputPath: string | undefined;
  if (flags.output !== undefined) {
    outputPath = path.resolve(io.cwd, flags.output);
    if (await isInside(outputPath, root)) {
      io.stderr(
        'vibeguard: refusing to write the report inside the scanned project (VibeGuard never modifies it).\n' +
          'Write it elsewhere, e.g. --output "$RUNNER_TEMP/vibeguard.sarif", or redirect stdout.\n',
      );
      return ExitCode.UsageError;
    }
  }

  let settings: Settings;
  try {
    const loaded = await loadConfig(
      root,
      flags.config === undefined ? undefined : path.resolve(io.cwd, flags.config),
    );
    settings = resolveSettings(loaded.config, {
      ...(flags.failOn !== undefined ? { failOn: flags.failOn } : {}),
      ...(flags.minConfidence !== undefined ? { minConfidence: flags.minConfidence } : {}),
    });
  } catch (err) {
    if (err instanceof ConfigError) {
      io.stderr(`vibeguard: ${err.file}: ${err.message}\n`);
      return ExitCode.UsageError;
    }
    throw err;
  }

  const unknown = Object.keys(settings.rules).filter((id) => !rules.some((r) => r.meta.id === id));
  if (unknown.length > 0) {
    io.stderr(`vibeguard: config refers to unknown rule(s): ${unknown.join(', ')}\n`);
    return ExitCode.UsageError;
  }

  const result: ScanResult = await scan({ root, settings, rules });
  const reporter = REPORTERS.get(flags.format);
  if (!reporter) return ExitCode.UsageError; // unreachable: validated by parseFormat
  const color =
    flags.color !== false &&
    outputPath === undefined &&
    flags.format === 'terminal' &&
    io.stdoutIsTTY &&
    io.env['NO_COLOR'] === undefined;
  const text = reporter.render(result, {
    locale: flags.lang,
    color,
    toolVersion: toolVersion(),
    failOn: settings.failOn,
    minConfidence: settings.minConfidence,
  });

  if (outputPath !== undefined) await writeFile(outputPath, text, 'utf8');
  else io.stdout(text);

  return exitCodeFor(result, settings.failOn);
}

/** True when `candidate` (which may not exist yet) is `dir` or inside it, after resolving symlinks. */
async function isInside(candidate: string, dir: string): Promise<boolean> {
  const realDir = await realpath(dir);
  let parent = path.dirname(candidate);
  let suffix = path.basename(candidate);
  // Resolve the deepest existing ancestor so symlinked output dirs cannot escape the check.
  for (;;) {
    try {
      const realParent = await realpath(parent);
      const full = path.join(realParent, suffix);
      const rel = path.relative(realDir, full);
      return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    } catch {
      const up = path.dirname(parent);
      if (up === parent) return false;
      suffix = path.join(path.basename(parent), suffix);
      parent = up;
    }
  }
}
