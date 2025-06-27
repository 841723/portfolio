import { defineCollection, z } from "astro:content";
import { glob } from 'astro/loaders'; // Not available with legacy API


const walkthroughs = defineCollection({
    loader: glob({ pattern: ["**/*.md",'!dev-*'], base: "src/content/walkthroughs" }),
    schema: z.object({
        name: z.string(),
        slug: z.string(),
        difficulty: z.enum(["easy", "medium", "hard", "insane"]),
        os: z.enum(["linux", "windows"]),
        img: z.string().optional(),
        content: z.string().optional(), // Optional content field for markdown content
    }),
});

console.log("Walkthroughs collection defined with schema:", walkthroughs.type);

export const collections = { walkthroughs };


/*
name: Example Machine 
slug: example1
difficulty: hard
os: linux

img: https://labs.hackthebox.com/storage/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
*/