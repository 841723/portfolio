import { TAGS } from "./tags";
import { BASE_GITHUB_URL } from "./consts";

export const WEB_PROJECTS = [
    {
        title: "REFORMAS LAS CANTERAS",
        description:
            "WORK IN PROGRESS - Website page for a small kitchen and bathroom reform company. Check their services, projects, and contact them.",
        img: "/las-canteras/logo.jpg",
        used_tech: [TAGS.Astro, TAGS.Typescript, TAGS.TailwindCSS],
    },
    {
        title: "ASESIN-ADA",
        description:
            "Online game to play Cluedo with bots or your friends. Chat with them, find the killer, the weapon, and the room, and win the game.",
        img: "/asesin-ada/logo.png",
        gh_link: BASE_GITHUB_URL+"asesin-ada",
        used_tech: [
            TAGS.React,
            TAGS.NodeJs,
            TAGS.SocketIo,
            TAGS.CSS,
            TAGS.Python,
            TAGS.PostgreSQL,
        ],
    },
    {
        title: "PC ARP",
        description:
            "Ecommerce website inspired by PC Componentes. Search for products, filter, sort and add them to your cart. Purchase the ones you like.",
        img: "/pc-arp/logo_square.png",
        gh_link: BASE_GITHUB_URL+"pcarp",
        used_tech: [TAGS.HTML, TAGS.CSS, TAGS.JavaScript, TAGS.NodeJs, TAGS.PostgreSQL],
    },
    {
        title: "PORTFOLIO",
        description: "This portfolio you are seeing right now.",
        img: "/portfolio/logo.png",
        gh_link: BASE_GITHUB_URL+"portfolio",
        preview_link: "https://841723.github.io/portfolio/",
        used_tech: [TAGS.Astro, TAGS.Typescript, TAGS.TailwindCSS],
    },
];