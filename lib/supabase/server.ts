import 'server-only'

import { cookies } from 'next/headers'
import { createServerClient } from '@supabase/ssr'

import { supabaseAnonKey, supabaseUrl } from '@/lib/env'

/**
 * The request-scoped Supabase client used by every page, server action and route
 * handler. It carries the user's own JWT, so row level security applies to it.
 *
 * @supabase/ssr 0.12 exposes cookies through getAll/setAll only; the older
 * get/set/remove trio is deprecated and must not be used.
 */
export async function createSupabaseServerClient() {
  const cookieStore = await cookies()

  return createServerClient(supabaseUrl(), supabaseAnonKey(), {
    cookies: {
      getAll() {
        return cookieStore.getAll()
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options)
          }
        } catch {
          // Server Components are not allowed to write cookies; proxy.ts already
          // refreshed the session on this request, so dropping them here is safe.
        }
      },
    },
  })
}
