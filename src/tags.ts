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
import AngularIcon from "./components/icons/Angular.astro";
import NumpyIcon from "./components/icons/Numpy.astro";
import PandasIcon from "./components/icons/Pandas.astro";
import STMIcon from "./components/icons/STM.astro";


export type TAGInfo = { name: string, style: string, icon: ((_props: Record<string, any>) => any), link: string | null };

export const TAGS = {
    React: {
        name: "React",
        style: "text-blue-100 bg-blue-500/60",
        icon: ReactIcon,
        link: "https://react.dev/",
    },
    NodeJs: {
        name: "Node.js",
        style: "text-green-100 bg-green-800/60",
        icon: NodeJsIcon,
        link: "https://nodejs.org",
    },
    SocketIo: {
        name: "Socket.io",
        style: "text-yellow-100 bg-yellow-700/60",
        icon: SocketIoIcon,
        link: "https://socket.io/",
    },
    PostgreSQL: {
        name: "PostgreSQL",
        style: "text-red-100 bg-red-700/60",
        icon: SQLIcon,
        link: "https://www.postgresql.org/",
    },
    SQLite: {
        name: "SQLite",
        style: "text-red-100 bg-red-700/60",
        icon: SQLIcon,
        link: "https://www.sqlite.org/",
    },
    HTML: {
        name: "HTML",
        style: "text-orange-100 bg-orange-600/60",
        icon: HTMLIcon,
        link: "https://developer.mozilla.org/en-US/docs/Web/HTML",
    },
    CSS: {
        name: "CSS",
        style: "text-blue-100 bg-blue-600/60",
        icon: CSSIcon,
        link: "https://developer.mozilla.org/en-US/docs/Web/CSS",
    },
    JavaScript: {
        name: "JavaScript",
        style: "text-black bg-yellow-400/60",
        icon: JavaScriptIcon,
        link: "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    },
    Cplusplus: {
        name: "C++",
        style: "text-blue-100 bg-blue-700/60",
        icon: CplusplusIcon,
        link: "https://cplusplus.com/",
    },
    TailwindCSS: {
        name: "TailwindCSS",
        style: "text-blue-100 bg-blue-300/60",
        icon: TailwindCSSIcon,
        link: "https://tailwindcss.com/",
    },
    Astro: {
        name: "Astro",
        style: "text-purple-100 bg-purple-400/60",
        icon: AstroIcon,
        link: "https://astro.build/",
    },
    Python: {
        name: "Python",
        style: "text-yellow-950 bg-yellow-300/60",
        icon: PythonIcon,
        link: "https://www.python.org/",
    },
    Java: {
        name: "Java",
        style: "text-black bg-orange-400/60",
        icon: JavaIcon,
        link: "https://www.java.com/en/",
    },
    JavaCC: {
        name: "JavaCC",
        style: "text-black bg-orange-400/60",
        icon: JavaIcon,
        link: "https://javacc.github.io/javacc/",
    },
    Android: {
        name: "Android",
        style: "text-green-100 bg-green-500/60",
        icon: AndroidIcon,
        link: "https://developer.android.com/studio",
    },
    Golang: {
        name: "Go",
        style: "text-blue-100 bg-blue-400/60",
        icon: GolangIcon,
        link: "https://go.dev/",
    },
    Wordpress: {
        name: "WordPress",
        style: "text-blue-100 bg-blue-800/60",
        icon: WordpressIcon,
        link: "https://wordpress.com/",
    },
    Assembly: {
        name: "ARM Assembly",
        style: "text-black bg-gray-100/60",
        icon: AssemblyIcon,
        link: "https://www.tutorialspoint.com/assembly_programming/index.htm",
    },
    AxureRP: {
        name: "Axure RP",
        style: "text-black bg-gray-200/60",
        icon: AxureRP,
        link: "https://www.axure.com/",
    },
    Typescript: {
        name: "TypeScript",
        style: "text-blue-100 bg-blue-700/60",
        icon: TypescriptIcon,
        link: "https://www.typescriptlang.org/",
    },
    Docker: {
        name: "Docker",
        style: "text-blue-100 bg-blue-400/60",
        icon: DockerIcon,
        link: "https://www.docker.com/",
    },
    Apache: {
        name: "Apache",
        style: "text-gray-200 bg-red-500/70",
        icon: ApacheIcon,
        link: "https://httpd.apache.org/",
    },
    Bash: {
        name: "Bash",
        style: "text-gray-950 bg-purple-300/60",
        icon: BashIcon,
        link: "https://devhints.io/bash",
    },
    Nginx: {
        name: "Nginx",
        style: "text-gray-200 bg-green-500/60",
        icon: NginxIcon,
        link: "https://nginx.org/en/",
    },
    Haskell: {
        name: "Haskell",
        style: "text-gray-300 bg-purple-900/60",
        icon: HaskellIcon,
        link: "https://www.haskell.org/",
    },
    Kubernetes: {
        name: "Kubernetes",
        style: "text-blue-100 bg-blue-700/60",
        icon: KubernetesIcon,
        link: "https://kubernetes.io/",
    },
    STM32: {
        name: "STM32",
        style: "text-black bg-yellow-400/60",
        icon: STMIcon,
        link: "https://www.st.com/en/microcontrollers-microprocessors/stm32-32-bit-arm-cortex-mcus.html",
    },
    Pandas: {
        name: "Pandas",
        style: "text-gray-300 bg-purple-950/60",
        icon: PandasIcon,
        link: "https://pandas.pydata.org/",
    },
    NumPy: {
        name: "NumPy",
        style: "text-blue-900 bg-blue-200/60",
        icon: NumpyIcon,
        link: "https://numpy.org/",
    },
    Angular: {
        name: "Angular",
        style: "text-black bg-pink-500/60",
        icon: AngularIcon,
        link: "https://angular.io/",
    },
};
