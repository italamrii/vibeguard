import { execFile } from 'node:child_process';
import { stat } from 'node:fs/promises';
import path from 'node:path';

/** Walk upwards from `start` to find the directory containing `.git` (dir or file). */
export async function findGitRoot(start: string): Promise<string | undefined> {
  let dir = path.resolve(start);
  for (;;) {
    try {
      await stat(path.join(dir, '.git'));
      return dir;
    } catch {
      // keep walking
    }
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/**
 * List files tracked by git under `root`, as posix paths relative to `root`.
 *
 * Security: the scanned repository may be untrusted, and its `.git/config` can name
 * programs that git runs implicitly (core.fsmonitor, core.hooksPath, …). We override the
 * known execution vectors on the command line, disable system/global config, and run
 * only `ls-files`, which needs no network. Returns `undefined` if git is unavailable or
 * fails for any reason; callers fall back to .gitignore semantics.
 */
export function listGitTrackedFiles(root: string): Promise<ReadonlySet<string> | undefined> {
  const args = [
    '-c',
    'core.fsmonitor=false',
    '-c',
    'core.hooksPath=/dev/null',
    '-c',
    'core.untrackedCache=false',
    '-c',
    'core.sshCommand=false',
    '-c',
    'protocol.allow=never',
    '-C',
    root,
    'ls-files',
    '-z',
    '--cached',
    '--',
    '.',
  ];
  return new Promise((resolve) => {
    execFile(
      'git',
      args,
      {
        timeout: 15_000,
        maxBuffer: 64 * 1024 * 1024,
        env: {
          PATH: process.env['PATH'] ?? '',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_OPTIONAL_LOCKS: '0',
          GIT_TERMINAL_PROMPT: '0',
          // Reading a repo owned by another user is refused by git >= 2.35.2 ("dubious
          // ownership"); we only read, so allow it for this one invocation.
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'safe.directory',
          GIT_CONFIG_VALUE_0: '*',
        },
        windowsHide: true,
      },
      (err, stdout) => {
        if (err) {
          resolve(undefined);
          return;
        }
        const files = stdout
          .split('\0')
          .filter((f) => f.length > 0)
          .map((f) => f.split(path.sep).join('/'));
        resolve(new Set(files));
      },
    );
  });
}
