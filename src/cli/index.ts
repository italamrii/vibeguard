#!/usr/bin/env node
import { scrubText } from '../core/redaction/redact.ts';
import { ExitCode } from './exit-codes.ts';
import { run } from './run.ts';

run(process.argv.slice(2), {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  stdoutIsTTY: process.stdout.isTTY,
  env: process.env,
  cwd: process.cwd(),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    // Unexpected internal error. Print a scrubbed message only: a stack trace or error
    // payload could include scanned file content.
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`vibeguard: internal error: ${scrubText(msg, { maxLength: 500 })}\n`);
    process.exitCode = ExitCode.ScanIncomplete;
  },
);
