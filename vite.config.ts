import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { createApiProxy, resolveApiProxyTarget } from './vite-proxy.js'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Dev-server only: bridge same-origin /v1 calls to the separately running API.
  server: {
    proxy: createApiProxy(resolveApiProxyTarget(process.env.VITE_API_PROXY_TARGET)),
  },
})
