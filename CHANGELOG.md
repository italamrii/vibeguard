# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/). Rule ids, exit codes, the JSON schema and the
SARIF fingerprint key are public API.

## [Unreleased]

## [0.1.0] - unreleased

First release, published as `@italamrii/vibeguard` (command: `vibeguard`).

### Added

- Local, read-only, offline static scanner: no network calls, never modifies or executes
  the scanned project. Secrets are redacted to the first 4 characters plus the length in
  every output.
- **Secrets** rules: `secrets/provider-key`, `secrets/provider-key-test`,
  `secrets/private-key`, `secrets/high-entropy`, `secrets/env-file-committed`,
  `secrets/client-exposed-env`.
- **Supabase** rules (SQL migrations replayed with the real Postgres parser):
  `supabase/rls-disabled`, `supabase/rls-no-policies`, `supabase/permissive-policy`,
  `supabase/service-role-in-client`, `supabase/security-definer-view`,
  `supabase/security-definer-function`.
- **Endpoints** rules (Next.js, Vercel functions, Express, Fastify):
  `endpoints/unauthenticated-data-access`, `endpoints/cors-wildcard-credentials`,
  `endpoints/auth-route-no-rate-limit`, `endpoints/webhook-without-signature`.
- Output formats: terminal, JSON (with a JSON Schema), SARIF 2.1.0 for GitHub code scanning,
  and Markdown. Reports in English and Arabic (`--lang ar`), right-to-left safe.
- Inline suppressions with a required reason; `.vibeguard.yml` configuration.
- Exit codes 0/1/2/3, failing closed: an incomplete scan never reports as clean.
- Documentation for every rule in `docs/rules/`.

[Unreleased]: https://github.com/italamrii/vibeguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/italamrii/vibeguard/releases/tag/v0.1.0
