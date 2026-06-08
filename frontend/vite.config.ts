import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

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
    proxy: {
      // In Docker, the backend is reachable via the compose service name; set
      // VITE_API_PROXY_TARGET=http://backend:8000. Falls back to localhost for
      // running the backend directly on the host.
      '/api': process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000',
    },
  },
})
