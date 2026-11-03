# Configuration

VibeGuard reads `.vibeguard.yml` (or `.vibeguard.yaml`) from the scan root, or the file
given with `--config`. Every key is optional except `version`. Unknown keys are an error,
so a typo can never silently disable a check.

> **CI and untrusted code:** the scanned repository controls its own `.vibeguard.yml`, so a
> pull request can weaken its own scan (for example by turning a rule off). When scanning
> code you don't fully trust, pass `--config` pointing to a file outside the checkout.

```yaml
version: 1

# Extra gitignore-style patterns to skip (relative to the scan root).
ignore:
  - 'e2e/**'
  - '*.generated.ts'

# Exit with code 1 when an unsuppressed finding is at or above this severity.
# critical | high | medium | low | none   (default: high; CLI --fail-on wins)
failOn: high

# Hide findings below this confidence (default: low = show everything, labelled).
minConfidence: low

# Turn rules off or change their severity.
rules:
  secrets/high-entropy: off
  supabase/permissive-policy: { severity: low }

discovery:
  # Skip build output and tool caches (default: true).
  skipBuildOutput: true
  # Directory *names* (matched at any depth) treated as build output.
  # Default: dist, build, out, coverage, storybook-static, .next, .nuxt, .svelte-kit,
  #          .output, .vercel, .netlify, .turbo, .expo, .cache, .parcel-cache
  # Override this when hand-written code lives in e.g. build/:
  buildOutputDirs: [dist, out, .next, coverage]

supabase:
  migrationsDirs: [supabase/migrations]
  exposedSchemas: [public] # default: read from supabase/config.toml, else [public]

endpoints:
  authFunctions: [requireUser] # extra functions that count as an auth check
  rateLimitFunctions: [limiter] # extra functions that count as rate limiting
```

## What is always skipped

`node_modules`, `.git`, `.hg`, `.svn`, `.yarn` and `.pnpm-store` are never scanned,
whatever the configuration. Lockfiles, binary files, source maps and `*.min.js` are never
read. Files over 5 MiB are skipped with a diagnostic. See
[ADR-0008](adr/0008-discovery.md).

## Inline suppressions

```ts
// vibeguard-ignore-next-line secrets/high-entropy -- public sample value from the vendor docs
const sample = '...';
```

A rule id and a reason of at least 10 characters are required. See
[ADR-0004](adr/0004-suppression-design.md).
