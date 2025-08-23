import { defineConfig } from 'astro/config';

import tailwindcss from "@tailwindcss/vite";

import sitemap from "@astrojs/sitemap";


const site = 'https://841723.github.io/portfolio/';
const base = '/portfolio';

// https://astro.build/config
export default defineConfig({
    site,
    base,
    integrations: [
        sitemap()
    ],
    vite: { plugins: [tailwindcss()] },
    markdown: {
        shikiConfig: {
            // Tema claro y oscuro con buen contraste
            themes: {
                light: "github-light",
                dark: "github-dark-dimmed", // Más suave que github-dark
            },

            // No usar colores por defecto de Astro
            defaultColor: false,

            // Word wrap para evitar scroll horizontal
            wrap: true,

            // Aliases útiles para ciberseguridad
            langAlias: {
                sh: "bash",
                shell: "bash",
                ps1: "powershell",
                cjs: "javascript",
                js: "javascript",
                py: "python",
            },

            // Puedes añadir idiomas personalizados si usas algo muy específico
            langs: [],

            // Transformers para funcionalidades extra (opcional)
            transformers: [
                // Resaltado de líneas y palabras
                "transformer-highlight-line",
                "transformer-highlight-word",
            ],
        },
    },
});