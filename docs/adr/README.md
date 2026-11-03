# Architecture Decision Records

Each ADR records one significant decision: its context, the decision, and what follows from it.
ADRs are immutable once accepted. A later decision supersedes an earlier one with a new ADR or an
explicit amendment section, rather than by silently editing it.

| #    | Title                                                                                                   | Status   |
| ---- | ------------------------------------------------------------------------------------------------------- | -------- |
| 0001 | [Use the TypeScript compiler API (parse-only) for JS/TS analysis](0001-parser-choice.md)                | Accepted |
| 0002 | [Parse SQL migrations with libpg-query (WebAssembly build)](0002-sql-parser.md)                         | Accepted |
| 0003 | [Finding model with localized message IDs](0003-finding-model.md)                                       | Accepted |
| 0004 | [Inline suppressions require a rule id and a reason](0004-suppression-design.md)                        | Accepted |
| 0005 | [Redaction is enforced by the type system, with a scrubber as backstop](0005-redaction-and-evidence.md) | Accepted |
| 0006 | [Static rule registry; no runtime plugin loading](0006-rule-registry.md)                                | Accepted |
| 0007 | [Fixtures are templates; fake secrets are assembled at build time](0007-fixture-templates.md)           | Accepted |
| 0008 | [File discovery, .gitignore semantics and git-tracked files](0008-discovery.md)                         | Accepted |
| 0009 | [Exit codes and fail-closed scanning](0009-exit-codes-fail-closed.md)                                   | Accepted |
| 0010 | [Classifying modules as client or server code](0010-runtime-classification.md)                          | Accepted |
| 0011 | [License under Apache-2.0](0011-license.md)                                                             | Accepted |
| 0012 | [Detecting unauthenticated endpoints syntactically](0012-endpoint-auth-detection.md)                    | Accepted |
| 0013 | [Rendering Arabic: isolated LTR runs in files, no Arabic in terminals](0013-arabic-rtl-rendering.md)    | Accepted |
| 0014 | [SARIF 2.1.0 mapping for GitHub code scanning](0014-sarif-mapping.md)                                   | Accepted |
