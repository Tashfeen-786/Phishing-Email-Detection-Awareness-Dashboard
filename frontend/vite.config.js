import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The frontend NEVER calls the backend by absolute URL. Every request goes to a
// relative path such as /api/analyze, and this proxy forwards it to FastAPI.
//
// Why it matters: if the browser called http://127.0.0.1:8000 directly, the app
// would break the moment it is opened from any machine other than the one
// running the backend, and it would need CORS. A relative path plus a proxy
// works the same locally and behind any host.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    allowedHosts: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
