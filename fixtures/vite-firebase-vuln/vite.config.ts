import { defineConfig } from 'vite';

export default defineConfig({
  define: {
    // vg-expect: secrets/client-exposed-env
    'process.env.OPENAI_API_KEY': JSON.stringify(process.env.OPENAI_API_KEY),
    __APP_VERSION__: JSON.stringify('1.0.0'),
  },
});
