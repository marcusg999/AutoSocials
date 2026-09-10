/**
 * Layer 1 of the defence-in-depth chain.
 *
 * In Next.js 16 this file replaces middleware.ts, exports a function named
 * `proxy`, and always runs on the Node.js runtime (declaring `runtime` here is an
 * error). It refreshes the Supabase session, mints the CSRF token, sets the
 * security response headers, and turns away anyone who is not fully authenticated.
 *
 * It is NOT the last word. Next.js routes Server Functions as POSTs to the page
 * they are used on, so a matcher that misses a path also misses its actions.
 * Every page and every action therefore re-checks with requireMfaSession().
 */
import { randomBytes } from 'node:crypto'
import { NextResponse, type NextRequest } from 'next/server'

import { updateSession } from '@/lib/supabase/proxy'
import { attachCsrfCookie, issueCsrfToken } from '@/lib/security/csrf-token'
import {
  DASHBOARD_PATH,
  LOGIN_PATH,
  MFA_ENROLL_PATH,
  MFA_VERIFY_PATH,
  isPublicPath,
} from '@/lib/security/routes'
import { isProduction, supabaseOrigin } from '@/lib/env'

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const nonce = randomBytes(16).toString('base64')
  const csp = contentSecurityPolicy(nonce)

  // The session is resolved first because the CSRF token is signed over the user
  // it belongs to, so we cannot mint one until we know who is asking.
  //
  // Next.js reads the nonce back out of the request's CSP header and stamps it
  // onto its own inline scripts.
  const { response, user, aal } = await updateSession(request, {
    'x-nonce': nonce,
    'content-security-policy': csp,
  })

  // Minted onto the REQUEST as well as the response, so this request's own render
  // embeds the same value the browser is being told to store.
  const csrf = issueCsrfToken(request, user?.id ?? null)
  if (csrf.isNew) attachCsrfCookie(response, csrf.token)
  applySecurityHeaders(response, csp)


  const { pathname } = request.nextUrl
  const target = destinationFor(pathname, user !== null, aal?.currentLevel ?? null, aal?.nextLevel ?? null)

  if (target) return redirectPreservingSession(request, response, target, csp)
  return response
}

/** Returns the path this request should be sent to instead, or null to let it through. */
function destinationFor(
  pathname: string,
  signedIn: boolean,
  currentLevel: string | null,
  nextLevel: string | null,
): string | null {
  const fullyVerified = signedIn && currentLevel === 'aal2'
  // nextLevel of aal2 while currentLevel is aal1 means: a verified factor exists,
  // it just has not been challenged on this session yet.
  const mfaStep = nextLevel === 'aal2' ? MFA_VERIFY_PATH : MFA_ENROLL_PATH

  if (isPublicPath(pathname)) {
    if (fullyVerified) return DASHBOARD_PATH
    if (!signedIn) return pathname === LOGIN_PATH ? null : LOGIN_PATH
    return pathname === mfaStep ? null : mfaStep
  }

  // Everything not on the public list requires a complete aal2 session.
  if (!signedIn) return LOGIN_PATH
  if (!fullyVerified) return mfaStep
  return null
}

/**
 * Redirects without losing the cookies updateSession just refreshed. Dropping
 * them would sign the user out on every redirect.
 */
function redirectPreservingSession(
  request: NextRequest,
  source: NextResponse,
  pathname: string,
  csp: string,
): NextResponse {
  const url = request.nextUrl.clone()
  url.pathname = pathname
  url.search = ''

  const redirectResponse = NextResponse.redirect(url)
  for (const cookie of source.cookies.getAll()) {
    redirectResponse.cookies.set(cookie)
  }
  applySecurityHeaders(redirectResponse, csp)
  return redirectResponse
}

function applySecurityHeaders(response: NextResponse, csp: string): void {
  response.headers.set('Content-Security-Policy', csp)
  // Tells browsers to refuse plain HTTP to this host for the next two years.
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  response.headers.set('X-DNS-Prefetch-Control', 'off')
}

function contentSecurityPolicy(nonce: string): string {
  const supabase = supabaseOrigin()
  const connect = ["'self'", supabase, isProduction() ? null : 'ws:'].filter(Boolean).join(' ')

  // The dev server compiles with eval(); production gets nonce + strict-dynamic so
  // that no injected <script> can execute even if markup escaping ever fails.
  //
  // 'self' is deliberately absent from the production value: 'strict-dynamic' makes
  // browsers ignore every host and scheme expression, so listing it would only
  // suggest a protection that is not doing anything.
  const script = isProduction()
    ? `'nonce-${nonce}' 'strict-dynamic'`
    : `'self' 'nonce-${nonce}' 'unsafe-eval' 'unsafe-inline'`

  return [
    "default-src 'self'",
    `script-src ${script}`,
    // React streams inline styles; there is no nonce hook for them.
    "style-src 'self' 'unsafe-inline'",
    // data: is required for the TOTP enrolment QR code, which arrives as a data URL.
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src ${connect}`,
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    'upgrade-insecure-requests',
  ].join('; ')
}

export const config = {
  matcher: [
    // Everything except Next's own build output and genuinely static media.
    //
    // Files in `public/` are served from the root, so they can only be excluded by
    // extension. The list is restricted to formats that cannot carry application
    // data -- images, fonts, media. Data-bearing extensions are deliberately NOT
    // here: a `.json`, `.txt`, `.xml` or `.csv` route is exactly the shape an
    // export endpoint takes, and exempting it would leave it unguarded and without
    // security headers on the day someone adds one.
    '/((?!_next/static|_next/image|favicon\\.ico$|.*\\.(?:svg|png|jpg|jpeg|gif|webp|avif|ico|woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav)$).*)',
  ],
}
