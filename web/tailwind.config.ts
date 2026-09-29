import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07090b",
        panel: "#0d1115",
        line: "#202a32",
        signal: "#64f4ac",
        warning: "#f4c264",
        danger: "#ff6b7a",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        signal: "0 0 24px rgba(100, 244, 172, 0.12)",
      },
    },
  },
  plugins: [],
} satisfies Config;
