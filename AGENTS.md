# AGENTS.md

## Stack
Astro 7 static site with Tailwind CSS v4 (via the `@tailwindcss/vite` plugin in `astro.config.mjs`; `tailwind.config.mjs` is legacy and unused). TypeScript strict via `astro/tsconfigs/strict`. Path alias `@/*` → `src/*`.

## Commands
- `npm run dev` / `npm run dev-host` — dev server (host variant exposes on LAN)
- `npm run build` — runs `astro check && astro build`; `astro check` is the only typecheck in the repo
- `npm run preview` — preview built `dist/`
- No test suite and no lint script. Prettier is installed but not wired to any script or config.

## Node version requirement
The active `node` is v20.20.0, which Astro 7 rejects (requires >=22.12.0). Run `source ~/.nvm/nvm.sh && nvm use 24` (v24.18.1 is installed) before any npm script, or `astro` fails to start.

## Content collections (`src/content.config.ts`, glob-based loaders)
- **writeups**: `src/content/writeups/**/*.md`. `*.devmd` files and `cheatsheet.md` are excluded from the build (`.devmd` = drafts; `template.devmd` is a scratch template). Required frontmatter: `name`, `difficulty` (easy|medium|hard|insane), `os` (linux|windows), `platform` (htb|vulnhub|other), `img`.
- **workexperiences, certs, projects**: YAML under `src/content/<name>/`; files named `dev-*` are excluded.
- **projects**: `used_tech` values must be valid `TAGS` keys from `src/tags.ts` (schema validates against them). Set `featured: true` to show a project in the featured section instead of the main list.
- Writeup body images use relative paths `images/<machine>/<file>.png`, stored in `src/content/writeups/images/<machine>/` (Astro optimizes them at build).
- Writeups are gated by `releasedDate`: content stays locked (HTB policy) until that date passes — expected behavior, not a bug.

## Data & i18n
- The site is English-only. No i18n is configured in `astro.config.mjs`; UI copy lives in `src/web-content/common.json`, read via `getWebLabel("key")` from `src/getWebLabel.ts`. Don't hardcode UI strings in components.

## Deploy
GitHub Pages via `.github/workflows/deploy.yml` (`withastro/action`): on push to `main`, a nightly cron, and manual dispatch. Site base is `/`; canonical URL is `https://diego.roldanu.es` (set in `astro.config.mjs`). Reference assets through `BASE_URL` (`src/consts.ts`) / `getImgUrl` (`src/uri.ts`) so paths stay correct on the Pages base path.
