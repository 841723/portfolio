# Diego Roldan — Portfolio

Personal portfolio for Diego Roldan, a cybersecurity analyst and full-stack developer. The site presents professional experience, certifications, projects, technical skills, and cybersecurity writeups.

**Live website:** [diego.roldanu.es](https://diego.roldanu.es)

## What the website includes

- **Introduction and contact links** — short profile, plus LinkedIn and GitHub links.
- **Work experience** — roles and descriptions presented as a timeline.
- **Certifications** — earned certifications and a separate in-progress section.
- **Cybersecurity writeups** — a preview on the home page and a complete list at `/writeups`, with name search and difficulty filters (Easy, Medium, Hard, Insane). Individual writeups include machine details, formatted Markdown, syntax-highlighted code, and a copy-code button.
- **Featured projects and more projects** — project cards with descriptions, technologies, source-code links, and/or live previews when provided.
- **Technical skills** — technologies grouped into Frontend, Backend, Blue Team, Red Team, Cloud, and Others.
- **Responsive navigation and layout** — mobile menu, dark visual theme, and page transitions.
- **Static-site and search-engine support** — generated sitemap, `robots.txt`, page metadata, and a custom 404 page.

Writeups with a future `releasedDate` are intentionally shown as locked until that date has passed, in accordance with Hack The Box's active-machine policy.

## Built with

- [Astro 7](https://astro.build/) and TypeScript (strict mode)
- [Tailwind CSS 4](https://tailwindcss.com/) via the Vite plugin
- Astro content collections for writeups, work experience, certifications, and projects
- GitHub Pages for deployment, using GitHub Actions

## Run locally

**Requirements:** Node.js `>=22.12.0` and npm.

```sh
npm install
npm run dev
```

The development server prints its local URL (usually `http://localhost:4321`). To expose it on the local network, run `npm run dev-host` instead.

Useful commands:

| Command | Description |
| --- | --- |
| `npm run dev` | Start the local development server |
| `npm run dev-host` | Start the development server and expose it on the network |
| `npm run build` | Run `astro check` and build the static site into `dist/` |
| `npm run preview` | Preview the production build locally |

## Content and project structure

Most portfolio content is data-driven. Update the files under `src/content/` to change the entries shown on the site:

- `src/content/workexperiences/*.yaml` — work history
- `src/content/certs/*.yaml` — certifications; set `blocked: true` for an in-progress entry
- `src/content/projects/**/*.yaml` — project cards; set `featured: true` to put a project in Featured Projects
- `src/content/writeups/**/*.md` — machine writeups and their required frontmatter
- `src/content/writeups/images/<machine>/` — images referenced by writeups using relative paths such as `images/<machine>/<file>.png`

The collection schemas and accepted fields are defined in `src/content.config.ts`. Project `used_tech` entries must match a tag in `src/tags.ts`. Writeup drafts (`*.devmd`) and `cheatsheet.md` are excluded from the site build. A writeup's `releasedDate` controls when its content becomes available.

Other useful locations:

- `src/components/` — page sections, cards, navigation, and icons
- `src/web-content/common.json` — shared interface labels and portfolio copy
- `src/techstack.ts` and `src/tags.ts` — skills displayed on the site and valid technology tags
- `public/` — static assets served as-is
- `astro.config.mjs` — Astro configuration, canonical site URL, sitemap, and Markdown code highlighting

## Deployment

The GitHub Actions workflow in `.github/workflows/deploy.yml` builds and deploys the site to GitHub Pages when changes are pushed to `main`. It can also be run manually and is scheduled to deploy nightly. The canonical URL is configured in `astro.config.mjs`.
