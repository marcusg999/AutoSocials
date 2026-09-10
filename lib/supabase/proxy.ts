import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'
import type { SupabaseClient, User } from '@supabase/supabase-js'

import { supabaseAnonKey, supabaseUrl } from '@/lib/env'

export type AalState = {
  currentLevel: string | null
  nextLevel: string | null
}

export type ProxySession = {
  /** The response the proxy MUST return (or copy cookies from) so the session survives. */
  response: NextResponse
  supabase: SupabaseClient
  user: User | null
  aal: AalState | null
}

/** Builds a pass-through response, forwarding the (possibly mutated) request plus our extra headers. */
function passThrough(request: NextRequest, extraRequestHeaders: Record<string, string>): NextResponse {
  const headers = new Headers(request.headers)
  for (const [name, value] of Object.entries(extraRequestHeaders)) {
    headers.set(name, value)
  }
  return NextResponse.next({ request: { headers } })
}

/**
 * Refreshes the Supabase session cookies for this request and reports who the
 * user is and how strongly they are authenticated.
 *
 * The returned `response` is the object the refreshed cookies were written to.
 * Returning a different response, or rebuilding this one, silently logs users out.
 */
export async function updateSession(
  request: NextRequest,
  extraRequestHeaders: Record<string, string> = {},
): Promise<ProxySession> {
  let response = passThrough(request, extraRequestHeaders)

  const supabase = createServerClient(supabaseUrl(), supabaseAnonKey(), {
    cookies: {
      getAll() {
        return request.cookies.getAll()
      },
      setAll(cookiesToSet) {
        // Write to the request first so the page render sees the fresh session,
        // then rebuild the response so it carries the same cookies to the browser.
        for (const { name, value } of cookiesToSet) {
          request.cookies.set(name, value)
        }
        response = passThrough(request, extraRequestHeaders)
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options)
        }
      },
    },
  })

  // getUser() revalidates the token against the auth server. getSession() only
  // decodes a cookie the client could have forged, so it is never used here.
  const { data: userData } = await supabase.auth.getUser()
  const user = userData.user ?? null

  let aal: AalState | null = null
  if (user) {
    const { data } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
    aal = data ? { currentLevel: data.currentLevel, nextLevel: data.nextLevel } : null
  }

  return { response, supabase, user, aal }
}
