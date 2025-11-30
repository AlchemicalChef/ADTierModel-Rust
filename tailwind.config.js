/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Tier-specific colors
        tier0: {
          light: "#fef2f2",
          DEFAULT: "#dc2626",
          dark: "#991b1b",
          border: "#fecaca",
          text: "#7f1d1d",
        },
        tier1: {
          light: "#fefce8",
          DEFAULT: "#ca8a04",
          dark: "#854d0e",
          border: "#fef08a",
          text: "#713f12",
        },
        tier2: {
          light: "#f0fdf4",
          DEFAULT: "#16a34a",
          dark: "#166534",
          border: "#bbf7d0",
          text: "#14532d",
        },
        // Status colors
        status: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#ca8a04",
          low: "#16a34a",
          info: "#2563eb",
        },
        // Dark mode surfaces
        surface: {
          50: "#f8fafc",
          100: "#f1f5f9",
          200: "#e2e8f0",
          800: "#1e293b",
          850: "#172033",
          900: "#0f172a",
          950: "#020617",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "fade-in": "fadeIn 0.2s ease-out",
        "slide-up": "slideUp 0.3s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
