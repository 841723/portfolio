import { TAGS } from "./tags";
import { BASE_GITHUB_URL } from "./consts";

export const OTHER_PROJECTS = [
    {
        title: "RAFT - DISTRIBUTED CONSENSUS",
        description:
            "A distributed consensus algorithm that ensures that all the nodes in a cluster agree on the same value.",
        img: "/raft/states.png",
        gh_link: BASE_GITHUB_URL + "raft",
        used_tech: [TAGS.Golang],
    },
    {
        title: "BETRIS",
        description:
            "Given a list of pieces, betris solves the problem of finding a way to fill a given number of rows. Shows visualization of the process.",
        img: "/betris/logo.png",
        gh_link: BASE_GITHUB_URL + "betris",
        preview_link: "https://www.onlinegdb.com/FR-2BJYjj",
        used_tech: [TAGS.Cplusplus],
    },
    {
        title: "FLEET-FEAST",
        description:
            "An android app that helps a restaurant owner to manage their restaurant. Orders and plates can be added, updated and deleted.",
        img: "/fleet-feast/logo.jpg",
        gh_link: BASE_GITHUB_URL + "fleet-feast",
        used_tech: [TAGS.Java, TAGS.Android, TAGS.SQLite],
    },
    {
        title: "ALIKE COMPILER",
        description:
            "Alike is a programming language similar to Ada. This project compiles Alike language and transforms into intermediate code which can be executed by P-machine.",
        img: "/alike/logo.jpg",
        gh_link: BASE_GITHUB_URL + "alike",
        used_tech: [TAGS.JavaCC],
    },
    {
        title: "RAN - TRAVEL APP",
        description:
            "A travel app designed to assist older travelers. Users can book activities, tours, and more. Guides can create new activities and chat with users.",
        img: "/ran/logo.jpg",
        gh_link: BASE_GITHUB_URL + "ran",
        used_tech: [TAGS.AxureRP],
    },
    {
        title: "CAR GAME ASSEMBLY",
        description:
            "A car game developed using assembly language. The user-controlled car must avoid touching the moving walls. It also supports 2 players simultaneously.",
        img: "/car-assembly/logo.jpg",
        gh_link: BASE_GITHUB_URL + "car-assembly",
        used_tech: [TAGS.Assembly],
    },
];
