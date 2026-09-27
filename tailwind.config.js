/** @type {import('tailwindcss').Config} */

function withOpacity(variableName) {
  return ({ opacityValue }) => {
    if (opacityValue !== undefined) {
      return `rgba(var(${variableName}), ${opacityValue})`;
    }
    return `rgb(var(${variableName}))`;
  };
}

module.exports = {
  darkMode: 'class',
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: withOpacity("--color-bg-rgb"),
          deep: withOpacity("--color-deep-rgb"),
          elevated: withOpacity("--color-elevated-rgb"),
          secondary: withOpacity("--color-secondary-rgb"),
          border: withOpacity("--color-border-rgb"),
          borderSubtle: withOpacity("--color-border-subtle-rgb"),
          text: withOpacity("--color-text-rgb"),
          muted: withOpacity("--color-muted-rgb"),
          copper: withOpacity("--color-copper-rgb"),
          copperHover: withOpacity("--color-copper-hover-rgb"),
          copperGlow: "rgba(196, 122, 82, 0.15)",
          mint: withOpacity("--color-mint-rgb"),
          mintHover: withOpacity("--color-mint-hover-rgb"),
          mintGlow: "rgba(143, 184, 168, 0.15)",
          critical: withOpacity("--color-critical-rgb"),
          warning: withOpacity("--color-warning-rgb"),
          info: withOpacity("--color-info-rgb"),
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "Geist Mono",
          "IBM Plex Mono",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "blink": "blink 1s step-start infinite",
      },
      keyframes: {
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0" },
        },
      },
    },
  },
  plugins: [],
};
