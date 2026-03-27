import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       '#0d1117',
        surface:  '#161b22',
        border:   '#30363d',
        text:     '#e6edf3',
        muted:    '#8b949e',
        critical: '#f85149',
        warning:  '#d29922',
        info:     '#3fb950',
        accent:   '#58a6ff',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config;
