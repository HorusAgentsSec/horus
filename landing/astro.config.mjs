import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

export default defineConfig({
  output: 'static',
  adapter: node({ mode: 'standalone' }),
  build: {
    assets: '_astro',
  },
  security: {
    checkOrigin: false,
  },
});
