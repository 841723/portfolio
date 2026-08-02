import { BASE_URL } from "./consts";

const formatPath = (path: string) => {
    if (path.length === 0) return "";
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;

    return path.endsWith("/") ? normalizedPath.slice(0, -1) : normalizedPath;
}

export const getFullUrl = (path: string) => {
    if (path.startsWith("http://") || path.startsWith("https://")) {
        return path; // Return the path as is if it's already a full URL
    }
    const pathWithSlashes = formatPath(path);
    const baseURL = formatPath(BASE_URL);

    return `${baseURL}${pathWithSlashes}`
}

export const getImgUrl = (path: string) => {
    if (path.startsWith("http://") || path.startsWith("https://")) {
        return path; // Return the path as is if it's already a full URL
    }
    const pathWithSlashes = formatPath(path);
    const baseURL = formatPath(BASE_URL);
    
    return `${baseURL}${pathWithSlashes}`
}