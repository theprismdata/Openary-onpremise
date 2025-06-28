import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV)
  },
  server: {
    port: 3000,
    allowedHosts : true,
    // cors: true  // CORS 활성화
  },
  build: {
    outDir: 'dist'
  }
})