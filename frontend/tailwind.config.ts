import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0f1117',
        surface: '#161b22',
        border: '#30363d',
        accent: '#58a6ff',
        muted: '#8b949e',
        severity: {
          critical: '#ff4444',
          high: '#ff8c00',
          medium: '#ffd700',
          low: '#58a6ff',
          info: '#8b949e',
        },
        mode: {
          auto: '#3fb950',
          approval: '#d29922',
          suggest: '#8b949e',
        },
        // ── Horus palette (new visual direction: Egyptian night + liquid glass) ──
        // Lapis-dominant: lapis drives actions/nav, gold is for brand/detail accents.
        horus: {
          night: '#0A0E1A',     // obsidian / Nile-night base
          ivory: '#F4EFE6',     // warm off-white text
          gold: '#E8B94A',      // Eye-of-Horus gold (brand/detail)
          lapis: '#2C6BED',     // lapis lazuli (primary action/nav)
          turquoise: '#27C2B6', // faïence turquoise
          carnelian: '#D6453B', // carnelian red (danger)
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}

export default config
