import en from "./web-content/common.json"
const webLabels: Record<string, string | any> = en || {};

export const getWebLabel = (label: string) => {
    return webLabels[label] || label;
};
