import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { ErrorObject, Options } from 'ajv';

/**
 * Validator for the vendored OASIS SARIF 2.1.0 schema (draft-04; no network access).
 * Returns ajv error messages; empty when valid.
 *
 * ajv-draft-04 and ajv-formats are CommonJS; their default-export typings do not survive
 * NodeNext interop, so we load them with require() and declare the small surface we use.
 */
interface Validator {
  (data: unknown): boolean;
  errors?: ErrorObject[] | null;
}
interface AjvLike {
  compile(schema: object): Validator;
}
type AjvConstructor = new (options: Options) => AjvLike;

const require = createRequire(import.meta.url);
const Ajv = require('ajv-draft-04') as AjvConstructor;
const addFormats = require('ajv-formats') as (ajv: AjvLike) => AjvLike;

const schema = JSON.parse(
  readFileSync(new URL('../vendor/sarif-schema-2.1.0.json', import.meta.url), 'utf8'),
) as object;
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

export function sarifSchemaErrors(text: string): string[] {
  const ok = validate(JSON.parse(text));
  return ok ? [] : (validate.errors ?? []).map((e) => `${e.instancePath} ${e.message ?? ''}`);
}
