import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders"; // Not available with legacy API

const writeups = defineCollection({
    loader: glob({
        pattern: ["**/*.md", "!dev-*"],
        base: "src/content/writeups",
    }),
    schema: z.object({
        name: z.string(),
        difficulty: z.enum(["easy", "medium", "hard", "insane"]),
        os: z.enum(["linux", "windows"]),
        img: z.string().optional(),
        platform: z.enum(["htb", "vulnhub", "other"]), // Enum for platform type
        content: z.string().optional(), // Optional content field for markdown content
        date: z.string().optional(), // Optional date field for writeup date
    }),
});

console.log("Writeups collection defined with schema:", writeups.type);

export const collections = { writeups };
