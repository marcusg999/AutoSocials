/**
 * Every environment variable the app reads, in one place.
 *
 * Only the two NEXT_PUBLIC_ values may ever reach the browser: the Supabase URL
 * and the publishable anon key are designed to be public, and row level security
 * is what actually protects the data. Anything else is read server-side only.
 *
 * These are functions rather than module constants so that a missing variable
 * fails loudly on the request that needs it, instead of at build time.
 */

function required(name: string, value: string | undefined): string {
  if (!value || value.length === 0) {
    throw new Error(`Missing required environment variable: ${name}`)
  }
  return value
}

export function supabaseUrl(): string {
  // Written out in full so Next.js can statically inline it where it is allowed to.
  return required('NEXT_PUBLIC_SUPABASE_URL', process.env.NEXT_PUBLIC_SUPABASE_URL)
}

export function supabaseAnonKey(): string {
  return required('NEXT_PUBLIC_SUPABASE_ANON_KEY', process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
}

export function isProduction(): boolean {
  return process.env.NODE_ENV === 'production'
}

/** The Supabase origin, used to widen the connect-src of the Content-Security-Policy. */
export function supabaseOrigin(): string | null {
  const raw = process.env.NEXT_PUBLIC_SUPABASE_URL
  if (!raw) return null
  try {
    return new URL(raw).origin
  } catch {
    return null
  }
}
