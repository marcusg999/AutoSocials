import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./', import.meta.url)),
      // The real package throws outside a Server Component. See the stub for why.
      'server-only': fileURLToPath(new URL('./tests/stubs/server-only.ts', import.meta.url)),
    },
  },
  test: {
    // Each database test file builds its own database, so files must not race.
    setupFiles: ['./tests/setup.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
    // Both extensions. Collecting only .test.ts meant a test file written as .tsx
    // -- the natural extension for anything rendering a component -- would sit in
    // the repo, never run, and count as coverage to anyone reading the directory.
    include: ['tests/**/*.test.{ts,tsx}'],
  },
})
