/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: 'var(--bg-primary)',
          secondary: 'var(--bg-secondary)',
          panel: 'var(--bg-panel)',
          border: 'var(--border-subtle)',
          'border-active': 'var(--border-active)',
          text: 'var(--text-primary)',
          'text-muted': 'var(--text-secondary)',
          copper: 'var(--accent-copper)',
          'copper-glow': 'var(--accent-copper-glow)',
          mint: 'var(--accent-mint)',
          warning: 'var(--status-warning)',
          critical: 'var(--status-critical)',
          info: 'var(--status-info)',
        },
        dark: {
          bg: '#0B0C0D',
          secondary: '#101214',
          panel: '#151719',
          border: '#292C2F',
          text: '#E8E3D8',
          muted: '#9B9D9A',
          copper: '#C47A52',
          mint: '#8FB8A8',
          warning: '#D7A84D',
          critical: '#E05A5A',
          info: '#7E9BB8',
        },
        light: {
          bg: '#F3F2EE',
          secondary: '#E9E7E1',
          panel: '#FFFFFF',
          border: '#D7D4CC',
          text: '#191A1B',
          muted: '#666865',
          copper: '#B9653E',
          mint: '#568C78',
          warning: '#B88828',
          critical: '#C94B4B',
          info: '#4F7399',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'IBM Plex Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanline 8s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
      },
    },
  },
  plugins: [],
}
