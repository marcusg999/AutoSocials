/**
 * The route map both security layers agree on. Kept free of server-only imports
 * so proxy.ts can use it too.
 */
export const LOGIN_PATH = '/login'
export const MFA_ENROLL_PATH = '/mfa/enroll'
export const MFA_VERIFY_PATH = '/mfa/verify'
export const AUTH_CALLBACK_PATH = '/auth/callback'
export const DASHBOARD_PATH = '/dashboard'

/** The only paths reachable without a fully verified (aal2) session. */
export const PUBLIC_PATHS = [LOGIN_PATH, MFA_ENROLL_PATH, MFA_VERIFY_PATH, AUTH_CALLBACK_PATH] as const

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))
}
