import 'server-only'

import { createClient, type SupabaseClient } from '@supabase/supabase-js'

import { supabaseUrl } from '@/lib/env'

/**
 * A service-role Supabase client. It bypasses row level security entirely, so it
 * is used for exactly one thing in Phase 1: writing an audit row for a failed
 * login, where there is no authenticated session to write it under.
 *
 * `import 'server-only'` above makes the build fail if this module is ever pulled
 * into a Client Component, and the runtime check below is the second line of
 * defence in case a bundler ever resolves around that marker.
 */
export function createSupabaseAdminClient(): SupabaseClient {
  if (typeof window !== 'undefined') {
    throw new Error('lib/supabase/admin.ts was evaluated in a browser. This is a security bug.')
  }

  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!serviceRoleKey) {
    throw new Error('Missing required environment variable: SUPABASE_SERVICE_ROLE_KEY')
  }

  return createClient(supabaseUrl(), serviceRoleKey, {
    // No session is ever persisted for this client; it must not pick up or write
    // any user's cookies.
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  })
}
