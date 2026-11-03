import { opendir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import ignore from 'ignore';
import type { Diagnostic } from '../findings/finding.ts';
import {
  ALWAYS_SKIP_DIRS,
  classifyFile,
  DEFAULT_BUILD_OUTPUT_DIRS,
  type FileKind,
} from './file-kind.ts';
import { findGitRoot, listGitTrackedFiles } from './git-tracked.ts';
import { isIgnoredByScopes, loadIgnoreFile, type IgnoreScope } from './gitignore.ts';

export interface FileRecord {
  /** posix path relative to the scan root */
  readonly relPath: string;
  readonly absPath: string;
  readonly kind: FileKind;
  readonly size: number;
  /** Matched by a .gitignore rule (only reported for files we still need, e.g. .env). */
  readonly gitIgnored: boolean;
  /** `true`/`false` when the root is in a git work tree and git is available; else undefined. */
  readonly gitTracked: boolean | undefined;
}

export interface DiscoveryOptions {
  readonly root: string;
  /** Extra gitignore-syntax patterns from config, relative to the root. */
  readonly ignorePatterns?: readonly string[];
  /**
   * Directory names (matched at any depth) treated as build output and skipped.
   * Defaults to DEFAULT_BUILD_OUTPUT_DIRS; pass [] to scan build output.
   */
  readonly buildOutputDirs?: readonly string[];
  /** Files above this size are skipped with a diagnostic. */
  readonly maxFileBytes?: number;
}

export interface DiscoveryResult {
  readonly root: string;
  readonly files: readonly FileRecord[];
  readonly diagnostics: readonly Diagnostic[];
  readonly gitRoot: string | undefined;
}

export const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
const DIR_CONCURRENCY = 32;

/**
 * Files that are gitignored are normally skipped, matching what would ship in the repo.
 * Exception: env files. A gitignored `.env` cannot leak through git, but we still need
 * to see it so the secrets rules can check for NEXT_PUBLIC_/VITE_ exposure (which leaks
 * through the client bundle regardless of git). The record carries `gitIgnored: true`
 * so rules can tell the two cases apart.
 */
function keepEvenIfIgnored(kind: FileKind): boolean {
  return kind === 'env';
}

export async function discoverFiles(opts: DiscoveryOptions): Promise<DiscoveryResult> {
  const root = await realpath(path.resolve(opts.root));
  const rootStat = await stat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`Scan root is not a directory: ${opts.root}`);
  }
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const skipDirs = new Set([
    ...ALWAYS_SKIP_DIRS,
    ...(opts.buildOutputDirs ?? DEFAULT_BUILD_OUTPUT_DIRS),
  ]);
  const diagnostics: Diagnostic[] = [];
  const files: FileRecord[] = [];

  const gitRoot = await findGitRoot(root);
  const tracked = gitRoot ? await listGitTrackedFiles(root) : undefined;
  if (gitRoot && !tracked) {
    diagnostics.push({ level: 'info', code: 'git-unavailable', params: {} });
  }
  // Directories that contain at least one tracked file. A file force-added with
  // `git add -f` inside an ignored directory is still committed, so we must descend there.
  const trackedDirs = new Set<string>();
  for (const f of tracked ?? []) {
    let d = path.posix.dirname(f);
    while (d !== '.' && !trackedDirs.has(d)) {
      trackedDirs.add(d);
      d = path.posix.dirname(d);
    }
  }

  // Ancestor scopes: .gitignore files between the git root and the scan root, plus
  // .git/info/exclude. Without a git root, only .gitignore files at/below the scan root apply.
  const baseScopes: IgnoreScope[] = [];
  if (gitRoot) {
    const exclude = await loadIgnoreFile(path.join(gitRoot, '.git', 'info', 'exclude'));
    const prefixFromGitRoot = toPosix(path.relative(gitRoot, root));
    if (exclude) baseScopes.push({ kind: 'ancestor', prefix: prefixFromGitRoot, matcher: exclude });
    let dir = gitRoot;
    const segments = prefixFromGitRoot === '' ? [] : prefixFromGitRoot.split('/');
    for (let i = 0; i < segments.length; i++) {
      const m = await loadIgnoreFile(path.join(dir, '.gitignore'));
      if (m) baseScopes.push({ kind: 'ancestor', prefix: segments.slice(i).join('/'), matcher: m });
      dir = path.join(dir, segments[i] ?? '');
    }
  }

  const configScope: IgnoreScope | undefined =
    opts.ignorePatterns && opts.ignorePatterns.length > 0
      ? { kind: 'within', base: '', matcher: ignore().add([...opts.ignorePatterns]) }
      : undefined;

  type Job = { abs: string; rel: string; scopes: readonly IgnoreScope[] };
  const queue: Job[] = [{ abs: root, rel: '', scopes: baseScopes }];
  let active = 0;

  await new Promise<void>((resolve, reject) => {
    const pump = (): void => {
      if (queue.length === 0 && active === 0) {
        resolve();
        return;
      }
      while (active < DIR_CONCURRENCY && queue.length > 0) {
        const job = queue.shift();
        if (!job) break;
        active++;
        processDir(job)
          .then(() => {
            active--;
            pump();
          })
          .catch(reject);
      }
    };

    const processDir = async (job: Job): Promise<void> => {
      const own = await loadIgnoreFile(path.join(job.abs, '.gitignore'));
      const scopes: IgnoreScope[] = own
        ? [...job.scopes, { kind: 'within', base: job.rel, matcher: own }]
        : [...job.scopes];
      const effective = configScope ? [...scopes, configScope] : scopes;

      let dir;
      try {
        dir = await opendir(job.abs);
      } catch {
        diagnostics.push({
          level: 'warning',
          code: 'file-unreadable',
          params: {},
          file: job.rel || '.',
        });
        return;
      }
      for await (const entry of dir) {
        const rel = job.rel === '' ? entry.name : `${job.rel}/${entry.name}`;
        const abs = path.join(job.abs, entry.name);
        if (entry.isSymbolicLink()) {
          // Never follow symlinks: they can point outside the root or create cycles.
          diagnostics.push({ level: 'info', code: 'symlink-skipped', params: {}, file: rel });
          continue;
        }
        if (entry.isDirectory()) {
          if (skipDirs.has(entry.name)) continue;
          if (isIgnoredByScopes(rel, true, effective) && !trackedDirs.has(rel)) {
            // Git never descends into an ignored directory, so its files cannot be
            // un-ignored; skipping it keeps big ignored trees (caches, vendored output) cheap.
            continue;
          }
          queue.push({ abs, rel, scopes });
          continue;
        }
        if (!entry.isFile()) continue;
        const kind = classifyFile(rel);
        if (kind === undefined) continue;
        const configIgnored = configScope ? isIgnoredByScopes(rel, false, [configScope]) : false;
        if (configIgnored) continue;
        const gitIgnored = isIgnoredByScopes(rel, false, scopes);
        const isTracked = tracked ? tracked.has(rel) : undefined;
        // A tracked file is in the repo regardless of .gitignore.
        if (gitIgnored && isTracked !== true && !keepEvenIfIgnored(kind)) continue;
        let size: number;
        try {
          size = (await stat(abs)).size;
        } catch {
          diagnostics.push({ level: 'warning', code: 'file-unreadable', params: {}, file: rel });
          continue;
        }
        if (size > maxBytes) {
          diagnostics.push({
            level: 'info',
            code: 'file-too-large',
            params: { size, limit: maxBytes },
            file: rel,
          });
          continue;
        }
        files.push({ relPath: rel, absPath: abs, kind, size, gitIgnored, gitTracked: isTracked });
      }
    };

    pump();
  });

  files.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));
  return { root, files, diagnostics, gitRoot };
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}
