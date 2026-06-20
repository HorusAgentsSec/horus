import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

// Document security headers. These must be real HTTP headers — the browser
// ignores X-Frame-Options, X-Content-Type-Options and CSP `frame-ancestors`
// when set via <meta http-equiv>. Mirrors the backend's API header policy.
const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self' https: wss:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; '),
}

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      manifest: {
        name: 'Horus',
        short_name: 'Horus',
        description: 'AI-native blue team security platform',
        start_url: '/',
        display: 'standalone',
        background_color: '#0f1117',
        theme_color: '#0f1117',
        icons: [
          { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
        ],
      },
    }),
  ],
  server: {
    // Applied to the Vite-served document in dev.
    headers: securityHeaders,
    proxy: {
      // In Docker, the backend is reachable via the compose service name; set
      // VITE_API_PROXY_TARGET=http://backend:8000. Falls back to localhost for
      // running the backend directly on the host.
      '/api': process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000',
    },
  },
  // `vite preview` serves the production build locally — same headers apply.
  // NOTE: dev/preview only. A production static host must set these headers
  // itself (especially X-Frame-Options / CSP frame-ancestors).
  preview: {
    headers: securityHeaders,
  },
})
