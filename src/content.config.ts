import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders"; // Not available with legacy API

import { TAGS } from "./tags";
// recupera todas las propiedades "name" de TAGS
type TagNames = (typeof TAGS)[keyof typeof TAGS]["name"];
// "react" | "vue" | "svelte"

const writeups = defineCollection({
    loader: glob({
        pattern: ["**/*.md", "!**/*.devmd", "!cheatsheet.md"]
       ,
       base: "src/content/writeups",
    }),
    schema: z.object({
        name: z.string(),
        difficulty: z.enum(["easy", "medium", "hard", "insane"]),
        os: z.enum(["linux", "windows"]),
        img: z.string().optional(),
        platform: z.enum(["htb", "vulnhub", "other"]),
        content: z.string().optional(),
        date: z.string().optional(), 
        releasedDate: z.date().optional(),
        userFlag: z.boolean().optional(),
        rootFlag: z.boolean().optional()
    }),
});

const workexperiences = defineCollection({
    loader: glob({
        pattern: ["**/*.yaml", "!dev-*"],
        base: "src/content/workexperiences",
    }),
    schema: z.object({
        position: z.string(),
        company: z.object({
            name: z.string(),
            color: z.string(),
            href: z.string(),
            bgcolor: z.string(),
        }),
        img: z.string(),
        date: z.string(),
        height: z.string(),
        description: z.string(),
        order: z.number().optional(),
    }),
});

const certs = defineCollection({
    loader: glob({
        pattern: ["**/*.yaml", "!dev-*"],
        base: "src/content/certs",
    }),
    schema: z.object({
        title: z.string(),
        description: z.string(),
        img: z.string(),
        date: z.string(),
        link: z.string().optional(),
        order: z.number().optional(),
        blocked: z.boolean().optional(),
    }),
});

const projects = defineCollection({
    loader: glob({
        pattern: ["**/*.yaml", "!dev-*"],
        base: "src/content/projects",
    }),
    schema: z.object({
        title: z.string(),
        description: z.string().optional(),
        descriptionHtml: z.string().optional(),
        img: z.string(),
        gh_link: z.string().optional(),
        preview_link: z.string().optional(),
        used_tech: z.array(z.enum(Object.values(TAGS).map(t => t.name) as [TagNames, ...TagNames[]])),
        order: z.number().optional(),
        featured: z.boolean().default(false),
    }),
});


export const collections = { 
  writeups,
  workexperiences, 
  certs,
  projects
} as const;
