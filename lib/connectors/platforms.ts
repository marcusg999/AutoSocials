/**
 * The platform names, matching the `social_platform` enum in 0003_content.sql.
 * Kept free of server-only imports so a client component could render a label.
 */
export const SOCIAL_PLATFORMS = [
  'facebook', 'instagram', 'x', 'tiktok', 'linkedin', 'youtube',
] as const

export type SocialPlatform = (typeof SOCIAL_PLATFORMS)[number]

export function isSocialPlatform(value: string): value is SocialPlatform {
  return (SOCIAL_PLATFORMS as readonly string[]).includes(value)
}

/** Platforms with a connector implemented. The rest are schema-only until built. */
export const CONNECTABLE_PLATFORMS: readonly SocialPlatform[] = ['facebook', 'instagram']
