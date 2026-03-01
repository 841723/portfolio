import { BASE_URL } from "./consts";
import { defaultlocale, getLocaleUrlPrefix, supportedLocales } from "./i18n";
import type { Locale } from "./types";

const formatPath = (path: string) => {
    if (path.length === 0) return "";
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;

    return path.endsWith("/") ? normalizedPath.slice(0, -1) : normalizedPath;
}

export const getFullUrl = (path: string, locale: Locale = defaultlocale) => {
    if (path.startsWith("http://") || path.startsWith("https://")) {
        return path; // Return the path as is if it's already a full URL
    }
    const pathWithSlashes = formatPath(path);
    const localePrefix = formatPath(getLocaleUrlPrefix(locale));
    const baseURL = formatPath(BASE_URL);

    return `${baseURL}${localePrefix}${pathWithSlashes}`
}

export const getImgUrl = (path: string) => {
    if (path.startsWith("http://") || path.startsWith("https://")) {
        return path; // Return the path as is if it's already a full URL
    }
    const pathWithSlashes = formatPath(path);
    const baseURL = formatPath(BASE_URL);
    
    return `${baseURL}${pathWithSlashes}`
}

export const removeLocale = (path: string) => {
    const supportedLocalePrefixes = Object.values(supportedLocales).map(formatPath);
    console.log("Supported locale prefixes:", supportedLocalePrefixes);
    const normalizedPath = formatPath(path);

    for (const prefix of supportedLocalePrefixes) {
        if (normalizedPath.startsWith(prefix)) {
            return normalizedPath.slice(prefix.length) || "/";
        }
    }
    return normalizedPath; // Return the original path if no locale prefix is found
}