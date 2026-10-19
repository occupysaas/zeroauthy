import { readFileSync } from 'node:fs'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig, type Plugin } from 'vitest/config'

// Ships the font's SIL OFL text next to the font files in dist/assets
// (OFL condition 2: each copy carries the license). Same-origin file, so
// the CSP is unaffected.
const fontLicense = (): Plugin => ({
  name: 'font-license',
  generateBundle() {
    this.emitFile({
      type: 'asset',
      fileName: 'assets/OFL.txt',
      source: readFileSync('src/assets/fonts/OFL.txt', 'utf8').replace(/\r\n/g, '\n'),
    })
  },
})

// The console is served by zeroauthy at /admin/ on the system host, from
// the committed dist/ (embedded with go:embed). No inline scripts or
// styles: the console's CSP allows only its own files.
export default defineConfig({
  base: '/admin/',
  plugins: [vue(), tailwindcss(), fontLicense()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.test.ts'],
  },
})
