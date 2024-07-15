import ReactIcon from "./components/icons/React.astro";
import NodeJsIcon from "./components/icons/NodeJs.astro";
import SocketIoIcon from "./components/icons/SocketIo.astro";
import SQLIcon from "./components/icons/SQL.astro";
import HTMLIcon from "./components/icons/HTML.astro";
import CSSIcon from "./components/icons/CSS.astro";
import JavaScriptIcon from "./components/icons/JavaScript.astro";
import CplusplusIcon from "./components/icons/Cplusplus.astro";
import TailwindCSSIcon from "./components/icons/TailwindCSS.astro";
import AstroIcon from "./components/icons/Astro.astro";
import PythonIcon from "./components/icons/Python.astro";
import JavaIcon from "./components/icons/Java.astro";
import AndroidIcon from "./components/icons/Android.astro";
import GolangIcon from "./components/icons/Golang.astro";
import WordpressIcon from "./components/icons/Wordpress.astro";
import AssemblyIcon from "./components/icons/Assembly.astro";
import TypescriptIcon from "./components/icons/Typescript.astro";
import AxureRP from "./components/icons/AxureRP.astro";
import DockerIcon from "./components/icons/Docker.astro";
import ApacheIcon from "./components/icons/Apache.astro";
import BashIcon from "./components/icons/Bash.astro";
import NginxIcon from "./components/icons/Nginx.astro";
import HaskellIcon from "./components/icons/Haskell.astro";
import KubernetesIcon from "./components/icons/Kubernetes.astro";


export type TAGInfo = { name: string, style: string, icon: ((_props: Record<string, any>) => any) | null };

export const TAGS = {
    React: { name: "React", style: "text-blue-100 bg-blue-500/60", icon: ReactIcon },
    NodeJs: { name: "Node.js", style: "text-green-100 bg-green-800/60", icon: NodeJsIcon },
    SocketIo: { name: "Socket.io", style: "text-yellow-100 bg-yellow-700/60", icon: SocketIoIcon },
    PostgreSQL: { name: "PostgreSQL", style: "text-red-100 bg-red-700/60", icon: SQLIcon },
    SQLite: { name: "SQLite", style: "text-red-100 bg-red-700/60", icon: SQLIcon },
    HTML: { name: "HTML", style: "text-orange-100 bg-orange-600/60", icon: HTMLIcon },
    CSS: { name: "CSS", style: "text-blue-100 bg-blue-600/60", icon: CSSIcon },
    JavaScript: { name: "JavaScript", style: "text-black bg-yellow-400/60", icon: JavaScriptIcon },
    Cplusplus: { name: "C++", style: "text-blue-100 bg-blue-700/60", icon: CplusplusIcon },
    TailwindCSS: { name: "TailwindCSS", style: "text-blue-100 bg-blue-300/60", icon: TailwindCSSIcon },
    Astro: { name: "Astro", style: "text-purple-100 bg-purple-400/60", icon: AstroIcon },
    Python: { name: "Python", style: "text-yellow-950 bg-yellow-300/60", icon: PythonIcon },
    Java: { name: "Java", style: "text-black bg-orange-400/60", icon: JavaIcon },
    JavaCC: { name: "JavaCC", style: "text-black bg-orange-400/60", icon: JavaIcon },
    Android: { name: "Android", style: "text-green-100 bg-green-500/60", icon: AndroidIcon },
    Golang: { name: "Go", style: "text-blue-100 bg-blue-400/60", icon: GolangIcon },
    Wordpress: { name: "WordPress", style: "text-blue-100 bg-blue-800/60", icon: WordpressIcon },
    Assembly: { name: "ARM Assembly", style: "text-black bg-gray-100/60", icon: AssemblyIcon },
    AxureRP: { name: "Axure RP", style: "text-black bg-gray-200/60", icon: AxureRP },
    Typescript: { name: "TypeScript", style: "text-blue-100 bg-blue-700/60", icon: TypescriptIcon },
    Docker: { name: "Docker", style: "text-blue-100 bg-blue-400/60", icon: DockerIcon },
    Apache: { name: "Apache", style: "text-gray-200 bg-red-500/70", icon: ApacheIcon },
    Bash: { name: "Bash", style: "text-gray-950 bg-purple-300/60", icon: BashIcon },
    Nginx: { name: "Nginx", style: "text-gray-200 bg-green-500/60", icon: NginxIcon },
    Haskell: { name: "Haskell", style: "text-gray-300 bg-purple-900/60", icon: HaskellIcon },
    Kubernetes: { name: "Kubernetes", style: "text-blue-100 bg-blue-700/60", icon: KubernetesIcon },
}
