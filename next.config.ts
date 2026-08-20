import type { NextConfig } from 'next'

// A production build with no APP_ORIGIN bakes `allowedOrigins: []` into the
// artifact, and Next then falls back to deriving the expected origin from forwarded
// headers -- the exact behaviour the comment below says it prevents. Fail the build
// instead of shipping a config that quietly does the opposite of what it claims.
if (process.env.NODE_ENV === 'production' && !process.env.APP_ORIGIN) {
  throw new Error(
    'APP_ORIGIN must be set for a production build. It is baked into '
    + 'serverActions.allowedOrigins, and without it Next.js falls back to trusting '
    + 'forwarded headers for its Server Action origin check.',
  )
}

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Don't advertise the framework version to attackers scanning response headers.
  poweredByHeader: false,
  typescript: { ignoreBuildErrors: false },
  experimental: {
    // Next.js performs its own origin check on Server Action POSTs, and by default
    // it derives the expected origin from the request's own forwarded headers.
    // Naming the origins explicitly means a spoofed X-Forwarded-Host cannot make a
    // cross-site POST look same-origin to Next either.
    serverActions: {
      allowedOrigins: (process.env.APP_ORIGIN ?? '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
        .map((value) => {
          try {
            return new URL(value).host
          } catch {
            return value
          }
        }),
    },
  },
}

export default nextConfig
