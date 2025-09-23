import en from './locales/en/common.json'
import es from './locales/es/common.json'
import type { Locale } from './types';

// const lang = Astro.cookies.get('lang')

const commons = {
    en,
    es
} as const;

export const defaultlocale: Locale = "en";

const tcommonsINT = (keyword: string, locale: Locale) => {
    // return commons[locale]?.[keyword] ?? commons[defaultlocale]?.[keyword] ?? "";

    // correct type-safe access
    if (locale in commons) {
        const localeCommons = commons[locale];
        if (keyword in localeCommons) {
            return localeCommons[keyword as keyof typeof localeCommons];
        } else {
            // fallback to default locale if key not found in specified locale
            const defaultCommons = commons[defaultlocale];
            return defaultCommons[keyword as keyof typeof defaultCommons] ?? "";
        }
    }
    // fallback to default locale
    const defaultCommons = commons[defaultlocale];
    return defaultCommons[keyword as keyof typeof defaultCommons] ?? "";
};


/*
    translation of a keyword using the common.json files
*/
export const tcommons = (locale: Locale) => (keyword: string) =>
    tcommonsINT(keyword, locale);

/*
    translation of an object:
    {
        "en": "Hello",
        "es": "Hola"
    }
*/
export const tobj = (locale: Locale) => 
     (locales: {
        "en":string,
        "es":string
    }) => locales[locale]


/*
    get the URL prefix for a given locale
        "en" -> ""
        "es" -> "/es"
*/
export const getLocaleUrlPrefix = (locale: Locale) =>
    locale === defaultlocale ? "" : `/${locale}`;


// export list of supported locales
export const supportedLocales: Locale[] = ["en", "es"];

export const currentLocale: Locale = "en";
