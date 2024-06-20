import { defineConfig } from 'astro/config';

import tailwind from "@astrojs/tailwind";

const site = 'https://841723.github.io';
const base = '/portfolio';

// const site = null;
// const base = null;

// https://astro.build/config
export default defineConfig({
  site,
  base,
  integrations: [tailwind()],
});