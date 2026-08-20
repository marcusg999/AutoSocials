/**
 * Test environment. These are throwaway values for the suite only — the real ones
 * live in the deployment environment and never in the repository.
 */
process.env.CSRF_SIGNING_SECRET ??= 'test-only-csrf-signing-secret-at-least-32-chars'
process.env.APP_ORIGIN ??= 'https://postdeck.example.com'
process.env.NEXT_PUBLIC_SUPABASE_URL ??= 'https://example.supabase.co'
process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??= 'test-anon-key'
process.env.ADMIN_DATABASE_URL ??= 'postgres://postdeck:postdeck@127.0.0.1:5432/postgres'
