/**
 * Scan mode: lets `scripts/check-no-secrets.ts` render authenticated pages so it can
 * look for leaked secrets in them.
 *
 * This exists because the alternative was worse. The scanner used to fetch every
 * route unauthenticated, which meant seven of eight routes were 307 redirects with
 * a six-byte body -- it reported "16 served responses scanned" while actually
 * inspecting one page, and it passed with the service-role key rendered on the
 * dashboard.
 *
 * A bypass is dangerous, so it is fenced four ways:
 *   1. It does nothing unless SECRET_SCAN_TOKEN is set. It is never set in a real
 *      deployment, and `.env.example` deliberately does not mention it.
 *   2. The request must present the same token in a header, compared in constant time.
 *   3. isScanModeConfigured() throws at startup if the token is set while APP_ORIGIN
 *      looks like a real deployment, so it cannot be switched on in production by
 *      accident.
 *   4. The scanner asserts every route rendered a document in at least one scan
 *      state; if this path ever stops working the scan fails loudly instead of
 *      quietly measuring redirects again.
 */
import { timingSafeEqual, createHash } from 'node:crypto'

export const SCAN_HEADER = 'x-postdeck-secret-scan'
export const SCAN_ACK_HEADER = 'x-postdeck-scan-ack'

/**
 * Which session state the scanner wants this request answered as.
 *
 * Without this the scanner could only ever see the app through a fully verified
 * session, so /mfa/enroll and /mfa/verify -- which redirect a verified user away --
 * could not render at all, and three of eight routes were measured as redirects
 * while the check reported "24 responses scanned". Varying the reported state does
 * not widen the bypass: the same token and the same local-origin fence gate it.
 */
export const SCAN_STATE_HEADER = 'x-postdeck-scan-state'

export type ScanSessionState = 'verified' | 'needs-verification' | 'needs-enrollment'

const SCAN_STATES: ScanSessionState[] = ['verified', 'needs-verification', 'needs-enrollment']

/** The state a scan request asked for, defaulting to a fully verified session. */
export function secretScanState(headerValue: string | null | undefined): ScanSessionState {
  const wanted = SCAN_STATES.find((state) => state === headerValue)
  return wanted ?? 'verified'
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = createHash('sha256').update(a).digest()
  const right = createHash('sha256').update(b).digest()
  return timingSafeEqual(left, right)
}

/** Throws if scan mode is switched on somewhere it must never be. */
function assertScanModeIsSafeHere(token: string): void {
  // Parse it rather than pattern-matching the raw string. `http://localhost:3000@evil.com`
  // has hostname `evil.com` -- `localhost:3000` is userinfo -- and a regex anchored on
  // the scheme happily calls that local.
  let hostname = ''
  try {
    hostname = new URL(process.env.APP_ORIGIN ?? '').hostname
  } catch {
    hostname = ''
  }
  const isLocal = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname)
  if (!isLocal) {
    throw new Error(
      'SECRET_SCAN_TOKEN is set but APP_ORIGIN is not a local address. '
      + 'Scan mode renders authenticated pages without a session and must never be '
      + 'enabled on a real deployment.',
    )
  }
  if (token.length < 32) {
    throw new Error('SECRET_SCAN_TOKEN must be at least 32 characters')
  }
}

/** True when this specific request is the secret scanner, and scan mode is allowed. */
export function isSecretScanRequest(headerValue: string | null | undefined): boolean {
  const token = process.env.SECRET_SCAN_TOKEN
  if (!token) return false
  assertScanModeIsSafeHere(token)
  if (!headerValue) return false
  return constantTimeEquals(token, headerValue)
}

/**
 * The value this app answers a scan request with, so the scanner can prove it is
 * reading the server it just built rather than whatever else holds the port.
 *
 * It is derived from the token, so only a process that already knows the token can
 * produce it -- which means an unrelated server squatting on the port cannot.
 */
export function scanAcknowledgement(token = process.env.SECRET_SCAN_TOKEN ?? ''): string {
  return createHash('sha256').update(`postdeck-scan-ack:${token}`).digest('hex')
}
