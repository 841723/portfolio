export type WorkExperienceItem = {
    date: string;
    title: string;
    company: Company;
    description: string;
    img: string;
    height?: string; // Optional height for the image
};

export type Company = {
    name: string;
    href: string;
    color?: string; // Optional color for the company name
}