import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import https from 'node:https'
import path from 'node:path'

const protectedProxyTarget = process.env.PROTECTED_PROXY_TARGET ?? 'https://localhost:10000'
const defaultCertDir = path.resolve('..', 'envoy', 'certs')
const protectedProxyCert = process.env.PROTECTED_PROXY_CERT ?? path.join(defaultCertDir, 'client.crt')
const protectedProxyKey = process.env.PROTECTED_PROXY_KEY ?? path.join(defaultCertDir, 'client.key')
const protectedProxyCa = process.env.PROTECTED_PROXY_CA ?? path.join(defaultCertDir, 'ca.crt')

function readIfExists(filePath: string) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/zt-protected': {
        target: protectedProxyTarget,
        changeOrigin: true,
        rewrite: (requestPath) => requestPath.replace(/^\/zt-protected/, ''),
        agent: new https.Agent({
          cert: readIfExists(protectedProxyCert),
          key: readIfExists(protectedProxyKey),
          ca: readIfExists(protectedProxyCa),
          rejectUnauthorized: false
        })
      }
    }
  }
})
