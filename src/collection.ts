import { getCollection } from "astro:content";

export const workexperiences = (await getCollection("workexperiences")).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

export const webprojects = (await getCollection("webprojects")).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

export const otherprojects = (await getCollection("otherprojects")).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

export const writeups = await getCollection("writeups")
