import path from 'node:path';

export type FileKind =
  'ts' | 'tsx' | 'js' | 'jsx' | 'sql' | 'env' | 'json' | 'yaml' | 'toml' | 'text';

export const CODE_KINDS: readonly FileKind[] = ['ts', 'tsx', 'js', 'jsx'];

/** Directories that are never scanned: dependencies, VCS data and build output. */
export const HARD_SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.vercel',
  '.netlify',
  '.turbo',
  '.output',
  '.expo',
  '.cache',
  '.parcel-cache',
  '.yarn',
  '.pnpm-store',
  'dist',
  'build',
  'out',
  'coverage',
  'storybook-static',
]);

/** Files that are machine-generated and cannot contain hand-written secrets or logic. */
const SKIP_FILE_NAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'bun.lock',
  'deno.lock',
]);

const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.avif',
  '.ico',
  '.bmp',
  '.tiff',
  '.psd',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.eot',
  '.mp3',
  '.mp4',
  '.mov',
  '.webm',
  '.wav',
  '.ogg',
  '.avi',
  '.zip',
  '.gz',
  '.tgz',
  '.bz2',
  '.xz',
  '.7z',
  '.rar',
  '.tar',
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.wasm',
  '.node',
  '.so',
  '.dylib',
  '.dll',
  '.exe',
  '.bin',
  '.class',
  '.jar',
  '.sqlite',
  '.db',
  '.lockb',
  '.map',
]);

const EXT_KIND: Readonly<Record<string, FileKind>> = {
  '.ts': 'ts',
  '.mts': 'ts',
  '.cts': 'ts',
  '.tsx': 'tsx',
  '.js': 'js',
  '.mjs': 'js',
  '.cjs': 'js',
  '.jsx': 'jsx',
  '.sql': 'sql',
  '.json': 'json',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.toml': 'toml',
};

/** `.env`, `.env.local`, `.env.production`, `prod.env`, … */
export function isEnvFileName(base: string): boolean {
  return base === '.env' || base.startsWith('.env.') || base.endsWith('.env');
}

/** Committed templates such as `.env.example` are expected to exist and hold placeholders. */
export function isEnvTemplateName(base: string): boolean {
  return (
    /\.(example|sample|template|dist|defaults?)$/i.test(base) ||
    /^\.env\.(example|sample|template)\b/i.test(base)
  );
}

/**
 * Classify a file by name. Returns `undefined` for files that should not be read at all
 * (binary, lockfiles, minified bundles).
 */
export function classifyFile(relPath: string): FileKind | undefined {
  const base = path.posix.basename(relPath);
  if (SKIP_FILE_NAMES.has(base)) return undefined;
  if (isEnvFileName(base)) return 'env';
  const ext = path.posix.extname(base).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return undefined;
  if (/\.min\.(js|mjs|cjs|css)$/i.test(base)) return undefined;
  return EXT_KIND[ext] ?? 'text';
}
