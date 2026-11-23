import { loadEnvFile } from 'node:process'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Browser-safe settings for deployed builds: `vite build` reads production.env
// and `vite build --mode staging` reads staging.env. Variables already set in
// the build environment take precedence.
const deployments = new Set(['production', 'staging'])

export default defineConfig(({ mode }) => {
  if (deployments.has(mode)) {
    loadEnvFile(new URL(`./${mode}.env`, import.meta.url))
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
