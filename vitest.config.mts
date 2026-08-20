import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Each database test file builds its own database, so files must not race.
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 90_000,
    include: ['tests/**/*.test.ts'],
  },
})
