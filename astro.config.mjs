import { defineConfig } from 'astro/config';

import tailwind from "@astrojs/tailwind";

// https://astro.build/config
export default defineConfig({
  site: 'https://841723.github.io',
  base: '/portfolio',
  integrations: [tailwind()],
  vite: {
    resolve: {
      alias: {
        '@layouts': '/src/layouts',
        '@components': '/src/components',
        '@icons': '/src/components/icons',
        '@src': '/src',

      }
    }
  }
});