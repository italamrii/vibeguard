# ADR-0010: Classifying modules as client or server code

- Status: Accepted
- Date: 2026-11-03

## Context

`supabase/service-role-in-client` (and the endpoint rules in a later phase) must know whether
a module ends up in the browser bundle. Precise answers need the bundler's module graph,
which needs project configuration, path aliases and dependency resolution, and that
conflicts with "never execute or resolve the scanned project".

## Decision

`src/analysis/runtime.ts` returns `client`, `server` or **`unknown`** with a confidence and a
human-readable reason (shown in the finding message). Signals, strongest first:

1. Directives and markers: `'use client'` → client (high). `'use server'` → server.
   `import 'server-only'` → server. `import 'client-only'` → client.
2. Server-only locations relative to the nearest `package.json`: `api/`, `server/`,
   `functions/`, `supabase/functions/`, `netlify/functions/`, `pages/api/`, route handlers
   (`route.ts`), `middleware.ts`, `*.server.*`, scripts, tool config files.
3. Framework conventions, from the nearest `package.json` dependencies:
   - Next.js App Router (`app/`, `src/app/`): Server Components by default → server (medium).
   - Next.js Pages Router (`pages/`, `src/pages/`): bundled for the browser → client (medium),
     except code inside `getServerSideProps` / `getStaticProps` / `getStaticPaths`, which the rule
     skips.
   - Vite / Create React App: `src/` → client (high). Expo: `src/`, `app/` → client.
4. Use of `import.meta.env.VITE_*` → client (medium).

Everything else is **unknown**, and rules report client-side problems only for `client`.
Shared modules (`lib/`, `components/` in Next.js) are unknown, because they become client
code only when imported from a client module. The rule covers the most common case with a
**one-level import check**: a client module that imports (via `./`, `../`, `@/` or `~/`) a
module that references the service-role key is reported at the import.

## Consequences

- Precision over recall: no transitive import graph, no `tsconfig` path aliases beyond
  `@/` and `~/`, no barrel-file following. A service-role client reaching the browser through two
  levels of imports is missed. This is documented in the threat model.
- The classifier is shared analysis code. Rules never re-implement it.
