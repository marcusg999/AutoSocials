import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Don't advertise the framework version to attackers scanning response headers.
  poweredByHeader: false,
  typescript: { ignoreBuildErrors: false },
}

export default nextConfig
