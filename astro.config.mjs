import { defineConfig } from 'astro/config';

import tailwind from "@astrojs/tailwind";

const site = 'https://841723.github.io';
const base = '/portfolio';

// https://astro.build/config
export default defineConfig({
  site,
  base,
  integrations: [tailwind()],
});