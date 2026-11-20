import { loadEnvFile } from 'node:process'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  if (mode === 'production') {
    loadEnvFile(new URL('./production.env', import.meta.url))
  }

  return {
    envDir: false,
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      fs: {
        // Preserve Vite's default protections and deny visible env files.
        deny: [
          '.env', '.env.*', '*.env', '*.env.*',
          '*.{crt,pem,key,p12,pfx,cer,der}', '.npmrc', '.yarnrc.yml', '**/.git/**',
        ],
      },
      proxy: { '/api': 'http://localhost:41932' },
    },
  }
})
