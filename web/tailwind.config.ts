import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#050807",
        panel: "#0b0f0d",
        panel2: "#111713",
        line: "#1c2420",
        muted: "#8a9a93",
        signal: "rgb(var(--signal) / <alpha-value>)",
        signalDeep: "rgb(var(--signal-deep) / <alpha-value>)",
        warning: "#f5c451",
        danger: "#ff6b6b",
      },
      fontFamily: {
        sans: [
          "'JetBrains Mono'",
          "ui-monospace",
          "'SF Mono'",
          "'Cascadia Code'",
          "Consolas",
          "monospace",
        ],
        mono: [
          "'JetBrains Mono'",
          "ui-monospace",
          "'SF Mono'",
          "'Cascadia Code'",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        signal: "0 0 1px rgb(var(--signal) / 0.45), 0 0 32px rgb(var(--signal) / 0.18)",
        glow: "0 8px 24px -8px rgb(var(--signal) / 0.5)",
        card: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 24px 48px -24px rgba(0,0,0,0.6)",
        elevated: "0 1px 0 0 rgba(255,255,255,0.05) inset, 0 32px 64px -28px rgba(0,0,0,0.7)",
      },
      backgroundImage: {
        "glass-panel": "linear-gradient(180deg, rgba(255,255,255,0.045), rgba(255,255,255,0.008))",
        "glass-panel-hover": "linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.015))",
        "signal-gradient": "linear-gradient(135deg, rgb(var(--signal)), rgb(var(--signal-deep)))",
        "glow-radial": "radial-gradient(circle at 50% 0%, rgb(var(--signal) / 0.18), transparent 70%)",
      },
      keyframes: {
        indeterminate: {
          "0%": { transform: "translateX(-100%)" },
          "60%": { transform: "translateX(220%)" },
          "100%": { transform: "translateX(220%)" },
        },
      },
      animation: {
        indeterminate: "indeterminate 1.3s cubic-bezier(0.4, 0, 0.2, 1) infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
