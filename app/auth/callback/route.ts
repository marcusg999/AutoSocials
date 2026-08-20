import { NextResponse, type NextRequest } from 'next/server'

import { createSupabaseServerClient } from '@/lib/supabase/server'
import { DASHBOARD_PATH, LOGIN_PATH } from '@/lib/security/routes'

export const dynamic = 'force-dynamic'

/**
 * Exchanges a Supabase auth code for a session cookie. It never returns tokens to
 * the browser: the session lives in httpOnly cookies written by @supabase/ssr.
 *
 * Landing here does not grant access to anything; the proxy and requireMfaSession()
 * still demand aal2 afterwards.
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const code = request.nextUrl.searchParams.get('code')
  if (!code) return NextResponse.redirect(new URL(`${LOGIN_PATH}?error=missing_code`, request.url))

  const supabase = await createSupabaseServerClient()
  const { error } = await supabase.auth.exchangeCodeForSession(code)
  if (error) {
    return NextResponse.redirect(new URL(`${LOGIN_PATH}?error=exchange_failed`, request.url))
  }

  return NextResponse.redirect(new URL(DASHBOARD_PATH, request.url))
}
