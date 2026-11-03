#!/usr/bin/env node
import { scrubText } from '../core/redaction/redact.ts';
import { ExitCode } from './exit-codes.ts';
import { isLocale } from '../i18n/locale.ts';
import { cliMessage, run } from './run.ts';

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
    // --lang is not parsed yet if the error happened early; look for it directly.
    const args = process.argv.slice(2);
    const i = args.findIndex((a) => a === '--lang' || a === '-l');
    const candidate = i >= 0 ? args[i + 1] : undefined;
    const lang = isLocale(candidate) ? candidate : 'en';
    process.stderr.write(
      cliMessage('internalError', { message: scrubText(msg, { maxLength: 500 }) }, lang),
    );
    process.exitCode = ExitCode.ScanIncomplete;
  },
);
