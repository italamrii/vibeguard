# ADR-0001: Use the TypeScript compiler API (parse-only) for JS/TS analysis

- Status: Accepted
- Date: 2026-11-03

## Context

The endpoint and client-exposure rules need real syntax trees for `.ts`, `.tsx`, `.js`,
`.jsx`, `.mjs` and `.cjs`. They need to find exported route handlers, `"use client"` and
`"use server"` directives, call expressions and object literals, and they need accurate
line and column positions. The tool must scan a 5,000-file repository in seconds, run on
Node 20 and 22 with no native build step, and never execute or resolve the scanned
project's code.

Options considered:

| Option                              | Pros                                                                                                       | Cons                                                                                                                                                                                 |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`typescript` `createSourceFile`** | The reference grammar for TS/TSX/JSX; error-tolerant; pure JS; positions are exact; no type checker needed | Large dependency (~23 MB unpacked); the AST API is verbose                                                                                                                           |
| `ts-morph`                          | Ergonomic wrapper                                                                                          | Builds a `Project`, so the per-file cost and memory are higher; it adds a dependency on top of `typescript` anyway; it encourages type-checker use that we cannot afford at 5k files |
| tree-sitter (native)                | Fast, multi-language                                                                                       | Native addon: prebuild and ABI issues on Node 20/22, Alpine and Windows; a separate grammar per language                                                                             |
| tree-sitter (WASM)                  | No native build                                                                                            | Async init, lags behind TS syntax, a different node model per grammar                                                                                                                |
| Babel parser                        | Fast, widely used                                                                                          | A second grammar for TS that diverges at the edges (decorators, `satisfies`, new syntax); we would still want TS for `.ts`                                                           |

## Decision

We use `typescript`'s `createSourceFile` with `setParentNodes: true` and JSDoc parsing
disabled. There is no `Program`, no type checker and no module resolution. Each file is
parsed independently and at most once per scan (memoized in `ProjectContext`). We pin
TypeScript 6.0.x. TypeScript 7 is the native Go port, and its JS API is not yet a stable
drop-in.

Files whose average line length exceeds 500 characters (minified or generated) are not
parsed into an AST. Text-based rules still see them.

## Consequences

- There is no type information. Rules reason syntactically, for example "this call is
  `.from()` on something named like a Supabase client". That is a source of both false
  negatives and false positives, which we manage with confidence levels and document per rule.
- There is no cross-file analysis in v1 (no import graph). A secret reaching client code
  through a shared module is a known limitation (see the threat model).
- Parsing never throws. The error count is available, so rules can lower confidence on
  badly broken files.
- Measured on Node 22: discovery plus reading 5,000 synthetic files takes about 0.9 s with
  no rules. Parse time is reported per phase in the README benchmark.
