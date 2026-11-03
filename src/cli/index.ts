#!/usr/bin/env node
import { scrubText } from '../core/redaction/redact.ts';
import { ExitCode } from './exit-codes.ts';
import { isLocale } from '../i18n/locale.ts';
import { cliMessage, run } from './run.ts';

/**
 * A reader that goes away early (`vibeguard rules | head -1`) makes further writes fail with
 * EPIPE. That is not an error of the scan: stop writing to that stream, let the scan finish,
 * and keep its exit code. Any other stream error is unexpected and makes the run incomplete.
 */
const closed = { stdout: false, stderr: false };
for (const name of ['stdout', 'stderr'] as const) {
  process[name].on('error', (err: NodeJS.ErrnoException) => {
    closed[name] = true;
    if (err.code !== 'EPIPE') process.exitCode = ExitCode.ScanIncomplete;
  });
}

run(process.argv.slice(2), {
  stdout: (s) => {
    if (!closed.stdout) process.stdout.write(s);
  },
  stderr: (s) => {
    if (!closed.stderr) process.stderr.write(s);
  },
  stdoutIsTTY: process.stdout.isTTY,
  env: process.env,
  cwd: process.cwd(),
}).then(
  (code) => {
    // A non-EPIPE stream failure already marked the run incomplete; never lower that.
    process.exitCode = Math.max(code, Number(process.exitCode ?? 0));
  },
  (err: unknown) => {
    // Unexpected internal error. Print a scrubbed message only: a stack trace or error
    // payload could include scanned file content.
    const msg = err instanceof Error ? err.message : String(err);
    // --lang is not parsed yet if the error happened early; look for it directly.
    const args = process.argv.slice(2);
    const i = args.findIndex((a) => a === '--lang' || a === '-l');
    const candidate = i >= 0 ? args[i + 1] : undefined;
    const lang = isLocale(candidate) ? candidate : 'en';
    if (!closed.stderr)
      process.stderr.write(
        cliMessage('internalError', { message: scrubText(msg, { maxLength: 500 }) }, lang),
      );
    process.exitCode = ExitCode.ScanIncomplete;
  },
);
