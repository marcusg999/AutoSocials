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

/**
 * The Meta (Facebook / Instagram) app credentials.
 *
 * Read only on the server, and only from here. Server actions are forbidden from
 * touching process.env at all — an action has several ways to hand a value to the
 * browser (a redirect target, a cookie, a header) and the secret scan reads none of
 * them, so the rule is enforced on the action module and configuration arrives
 * through a function like this one instead.
 */
export function metaAppCredentials(): { appId: string; appSecret: string } {
  return {
    appId: required('META_APP_ID', process.env.META_APP_ID),
    appSecret: required('META_APP_SECRET', process.env.META_APP_SECRET),
  }
}

/** True when a Meta app is configured at all, so the UI can say so instead of failing. */
export function isMetaConfigured(): boolean {
  return Boolean(process.env.META_APP_ID && process.env.META_APP_SECRET)
}

/**
 * The Anthropic API key, for the writing assistant.
 *
 * An app-level provider secret, so it lives in the environment alongside
 * META_APP_SECRET rather than in Supabase Vault — the Vault holds per-ACCOUNT
 * credentials, which are the ones that multiply and have to be revoked one at a
 * time. Like every other server-only value it is canaried by `npm run
 * test:secrets`, and it is read only here.
 */
export function anthropicApiKey(): string {
  return required('ANTHROPIC_API_KEY', process.env.ANTHROPIC_API_KEY)
}

/** True when the assistant is configured, so the UI can say so instead of failing. */
export function isAssistantConfigured(): boolean {
  return Boolean(process.env.ANTHROPIC_API_KEY)
}

/**
 * The OAuth redirect target, derived from APP_ORIGIN rather than from the request.
 *
 * Deriving it from a request header would let a caller choose where the provider
 * sends the code. It is the same reason the CSRF origin allowlist reads APP_ORIGIN
 * and never trusts a forwarded header.
 */
export function appOrigin(): string {
  const configured = process.env.APP_ORIGIN?.split(',')[0]?.trim()
  if (configured) return configured
  if (isProduction()) throw new Error('APP_ORIGIN must be set in production')
  return 'http://127.0.0.1:3000'
}
