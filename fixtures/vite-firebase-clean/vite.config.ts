import { defineConfig } from 'vite';

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify('1.0.0'),
    'import.meta.env.VITE_BUILD_SHA': JSON.stringify(process.env.GITHUB_SHA ?? 'dev'),
  },
});
