# ADR-0002: Parse SQL migrations with libpg-query (WebAssembly build)

- Status: Accepted
- Date: 2026-11-03

## Context

The Supabase rules must understand migrations precisely: `CREATE TABLE` (with
`IF NOT EXISTS`, quoting and schema qualification), `ALTER TABLE … ENABLE/DISABLE/FORCE ROW
LEVEL SECURITY`, renames, schema moves, `DROP`, `CREATE/ALTER/DROP POLICY` with their
`USING`/`WITH CHECK` expressions, `GRANT/REVOKE`, views and functions. Supabase migrations
routinely contain PL/pgSQL, dollar quoting, `DO` blocks and Postgres-only syntax.

Requirements: no native compilation (Node 20 and 22 on Linux, macOS and Windows); never crash
on bad input; never present unanalysed SQL as safe.

| Option                            | Pros                                                                                                                                                                                                                                                    | Cons                                                                                                                                |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **libpg-query 18 (WASM)**         | The actual Postgres parser (`libpg_query`, extracted from the server source), so the grammar matches the database. JSON AST with byte offsets, plus the Postgres lexer (`scanSync`). Prebuilt `.wasm` with no install script and no `binding.gyp`. MIT. | 1.8 MB. Asynchronous one-time load. Offsets are UTF-8 bytes. Booleans that are false are omitted from the JSON (protobuf defaults). |
| libpg-query (older native builds) | Same grammar                                                                                                                                                                                                                                            | `node-gyp` builds broke on Windows and Alpine, which is exactly what we must avoid                                                  |
| pgsql-ast-parser                  | Pure JS, sync                                                                                                                                                                                                                                           | A hand-written grammar that rejects a lot of real Postgres (PL/pgSQL bodies, many DDL forms)                                        |
| Regex                             | Trivial                                                                                                                                                                                                                                                 | Cannot read policy expressions, quoting or comments correctly, and fails on the tricky cases the rules exist for                    |

## Decision

- Use `libpg-query@18` (WebAssembly). Verified locally: `npm ci --ignore-scripts` followed by
  parsing works on Node 20.20 and 22.23, and the package contains no `.node` binaries or
  `binding.gyp`. CI job `sql-parser-portability` repeats this on ubuntu, macos and windows ×
  Node 20 and 22.
- **Robustness contract** (`src/core/parsing/sql-parser.ts`):
  1. Parse the whole file.
  2. On failure, split it into statements with the Postgres _lexer_, which works on
     syntactically invalid input and respects dollar quotes and comments, and parse each
     statement separately. One bad statement no longer hides the rest of the file.
  3. Statements that still fail come back as `failures`. If even the lexer fails (for
     example an unterminated quote), the whole file is one failure. The parser never throws.
- **Unparsed SQL is never treated as safe.** Each failure produces a `parse-failed`
  warning with file and line. The tables it names, found by a conservative identifier scan of
  the raw text, are marked _uncertain_. If no table can be identified, every table in that
  project is. Findings on uncertain tables get **low confidence** and an "unverified" message.
  `DO` blocks and function bodies that alter RLS or policies are treated the same way
  (`dynamic-sql` warning), because PL/pgSQL is not executed.
- Every reporter treats these notices (and `no-migrations`) as **partial coverage**. The report
  carries a banner, "No findings." becomes "No findings in the parts that could be analysed.
  Coverage is PARTIAL…", and JSON has `"partialCoverage": true`. The exit code is unaffected:
  partial coverage is a property of the report, not a crash (contrast ADR-0009's exit code 3).
- Replay order is migration filename order with numeric collation (Supabase prefixes are
  timestamps). Later statements override earlier ones, so the final state wins. Unqualified
  names resolve to `public`. Unquoted identifiers are case-folded, as Postgres does.

## Consequences

- Booleans must be read as `=== true` (absent means false). An early version read
  `permissive !== false`, which treated `AS RESTRICTIVE` policies as permissive; a unit test
  now pins this.
- Supabase state that never appears in a migration (dashboard edits, `supabase db pull`
  never run) is invisible. When a project uses Supabase but has no migrations, the
  `no-migrations` warning says so explicitly.
- `search_path` changes inside migrations are not modelled. Unqualified names always resolve to `public`.
