import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ENTRY = fileURLToPath(new URL('../../src/cli/index.ts', import.meta.url));

/** Run the real CLI entry point in a child process whose stdout reader goes away at once. */
function runWithClosedStdout(
  args: readonly string[],
): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', ENTRY, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    // Like `vibeguard rules | head -1`: the consumer closes the pipe before we write.
    child.stdout.destroy();
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stderr });
    });
  });
}

describe('CLI process behaviour', () => {
  it('exits quietly with its normal exit code when stdout is closed early (EPIPE)', async () => {
    const { code, stderr } = await runWithClosedStdout(['rules']);
    expect(stderr).not.toMatch(/EPIPE|Unhandled|at .*\.js:\d+/);
    expect(code).toBe(0);
  }, 30_000);
});
