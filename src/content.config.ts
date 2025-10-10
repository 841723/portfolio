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
        position: z.object({
            en: z.string(),
            es: z.string(),
        }),
        company: z.object({
            name: z.string(),
            color: z.string(),
            href: z.string(),
            bgcolor: z.string(),
        }),
        img: z.string(),
        date: z.string(),
        height: z.object({
            en: z.string(),
            es: z.string(),
        }),
        description: z.object({
            en: z.string(),
            es: z.string(),
        }),
        order: z.number().optional(),
    }),
});

const webprojects = defineCollection({
    type: "data",
    schema: z.object({
        title: z.object({
            en: z.string(),
            es: z.string(),
        }),
        description: z.object({
            en: z.string(),
            es: z.string(),
        }),
        img: z.string(),
        gh_link: z.string().optional(),
        preview_link: z.string().optional(),
        used_tech: z.array(z.enum(Object.values(TAGS).map(t => t.name) as [TagNames, ...TagNames[]])),
        order: z.number().optional(),
    }),
});

const otherprojects = defineCollection({
    type: "data",
    schema: z.object({
        title: z.object({
            en: z.string(),
            es: z.string(),
        }),
        description: z.object({
            en: z.string(),
            es: z.string(),
        }),
        img: z.string(),
        gh_link: z.string().optional(),
        preview_link: z.string().optional(),
        used_tech: z.array(z.enum(Object.values(TAGS).map(t => t.name) as [TagNames, ...TagNames[]])),
        order: z.number().optional(),
    }),

});


export const collections = { 
  writeups,
  workexperiences, 
  webprojects, 
  otherprojects
} as const;
