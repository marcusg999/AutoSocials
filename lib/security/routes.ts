/**
 * The route map both security layers agree on. Kept free of server-only imports
 * so proxy.ts can use it too.
 */
export const LOGIN_PATH = '/login'
export const MFA_ENROLL_PATH = '/mfa/enroll'
export const MFA_VERIFY_PATH = '/mfa/verify'
export const DASHBOARD_PATH = '/dashboard'

/** The only paths reachable without a fully verified (aal2) session. */
// Phase 1 signs in with email and password only. There is deliberately no
// /auth/callback code-exchange route: an endpoint that trades a query parameter
// for a session, and which by its nature must sit outside the auth guards, is
// real attack surface, and nothing in this phase needs it. Add it back with a
// state parameter bound to a cookie when a phase actually introduces OAuth.
export const PUBLIC_PATHS = [LOGIN_PATH, MFA_ENROLL_PATH, MFA_VERIFY_PATH] as const

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))
}
