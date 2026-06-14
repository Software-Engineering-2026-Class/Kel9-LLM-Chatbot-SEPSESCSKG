import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        sans: ["Space Mono", "monospace"],
      },
      colors: {
        background: "#060b16",
      },
      animation: {
        "bounce-slow": "bounce 1.4s infinite",
      },
    },
  },
  plugins: [],
};

export default config;