import en from './locales/en/common.json'
import es from './locales/en/common.json'

const commons = {
    en,
    es
} as const;
const defaultlocale = "en"

export const tcommons = (keyword: string, locale: "en" | "es") => 
    commons[locale]?.[keyword] ?? commons[defaultlocale]?.[keyword] ?? "";

export const tobj = (locale: "en" | "es") => 
     (locales: {
        "en":string,
        "es":string
    }) => locales[locale]
