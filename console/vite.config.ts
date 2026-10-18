import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

// The console is served by zeroauthy at /admin/ on the system host, from
// the committed dist/ (embedded with go:embed). No inline scripts or
// styles: the console's CSP allows only its own files.
export default defineConfig({
  base: '/admin/',
  plugins: [vue()],
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
