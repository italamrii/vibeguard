# ADR-0015: Packaging and release

- Status: Accepted
- Date: 2026-11-03

## Context

VibeGuard runs on code that may contain real secrets, and its own repository contains
intentionally vulnerable fixture templates. The published package must contain only what
the CLI needs at runtime, and a release must never happen by accident.

## Decision

- **Name:** `@italamrii/vibeguard`. The unscoped name `vibeguard` is free, but npm's
  similarity check would likely reject it because `vibe-guard` exists. The installed
  command stays `vibeguard`.
- **Contents by allowlist:** `files` lists `dist`, `schema` and `NOTICE` (npm adds
  `package.json`, `README.md` and `LICENSE`). The build emits JavaScript only: no source
  maps (they would point at sources that are not shipped) and no type declarations (v1
  has no programmatic API; `exports` exposes only `package.json` and the findings JSON
  Schema). No documentation is needed at runtime: reports link to the rule pages on GitHub.
- **Gate:** `npm run pack:check` fails when the tarball contains any path outside the
  allowlist or on a forbidden list (fixtures, templates, tests, scripts, sources, maps, env
  files), or when VibeGuard's secret signatures match anything in the unpacked tarball.
  CI then installs the tarball in a clean directory and runs the CLI on Node 20 and 22.
- **Dependencies:** runtime dependencies must be permissive and Apache-2.0-compatible;
  dev-only dependencies may also be MPL-2.0. CI fails on any runtime `npm audit` advisory.
- **Release:** only from the `release.yml` workflow, on a pushed `v*.*.*` tag, after a full
  re-verification, from the `npm-release` environment, which requires a reviewer's
  approval. It publishes with npm provenance. `publishConfig.provenance: true` makes a
  publish from a laptop fail, which is intended.

## Consequences

- Users who want a library API get none in v1. Adding one later means adding declarations
  and an `exports` entry, which is a minor version change.
- The tarball check must be updated when a new runtime file type is added.
- The publishing account must own the `@italamrii` npm scope.
