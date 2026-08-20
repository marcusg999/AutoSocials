import type { NextConfig } from 'next'

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
