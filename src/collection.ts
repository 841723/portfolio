import { getCollection } from "astro:content";

export const workexperiences = (await getCollection("workexperiences")).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

// export const webprojects = (await getCollection("webprojects")).sort((a, b) => {
//   return (a.data.order ?? 99999) - (b.data.order ?? 99999);
// });

// export const otherprojects = (await getCollection("otherprojects")).sort((a, b) => {
//   return (a.data.order ?? 99999) - (b.data.order ?? 99999);
// });

export const certs = (await getCollection("certs")).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

// export const homelabprojects = (await getCollection("homelabprojects")).sort((a, b) => {
//   return (a.data.order ?? 99999) - (b.data.order ?? 99999);
// });

export const projects = (await getCollection("projects")).filter((proj) => proj.data.featured !== true).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

export const featuredprojects = (await getCollection("projects")).filter((proj) => proj.data.featured === true).sort((a, b) => {
  return (a.data.order ?? 99999) - (b.data.order ?? 99999);
});

export const writeups = await getCollection("writeups")