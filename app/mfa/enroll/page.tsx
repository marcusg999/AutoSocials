import { redirect } from 'next/navigation'

import { csrfField } from '@/lib/security/csrf'
import { resolveSessionState } from '@/lib/security/session'
import { DASHBOARD_PATH, LOGIN_PATH, MFA_VERIFY_PATH } from '@/lib/security/routes'
import { signOutAction } from '@/app/actions'

import { confirmEnrollmentAction, restartEnrollmentAction } from './actions'

export const dynamic = 'force-dynamic'

const MESSAGES: Record<string, string> = {
  code_format: 'Enter the six digits shown in your authenticator app.',
  invalid_code: 'That code was not accepted. A fresh QR code is below — scan it, then try again.',
  unknown_factor: 'That enrolment expired. Scan the QR code below and try again.',
  challenge_failed: 'The authenticator challenge could not be started. Try again.',
}

export default async function EnrollPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>
}) {
  // Layer 2. The proxy already checked, and this page checks again independently.
  const state = await resolveSessionState()
  if (state.status === 'anonymous') redirect(LOGIN_PATH)
  if (state.status === 'verified') redirect(DASHBOARD_PATH)
  if (state.status === 'needs-verification') redirect(MFA_VERIFY_PATH)

  const { supabase } = state
  const { error } = await searchParams
  const message = error ? MESSAGES[error] ?? 'Enrolment could not be completed.' : null

  // A GET must not mutate. SameSite=Lax sends session cookies on top-level
  // cross-site navigation, so if rendering this page discarded and recreated the
  // user's pending factor, any website could churn it just by linking here.
  //
  // So: start an enrolment only when there is not one already. If a pending factor
  // exists we cannot show its QR again -- Supabase returns the QR once, at
  // creation -- so the page offers a "start over" button instead, which is a POST
  // and therefore CSRF-protected.
  const { data: existing } = await supabase.auth.mfa.listFactors()
  const pending = existing?.all?.find(
    (factor) => factor.factor_type === 'totp' && factor.status === 'unverified',
  )

  const { data: enrolled, error: enrollError } = pending
    ? { data: null, error: null }
    : await supabase.auth.mfa.enroll({ factorType: 'totp' })

  const factorId = enrolled?.id ?? pending?.id

  if (enrollError || !factorId) {
    return (
      <main className="shell narrow">
        <p className="brand">PostDeck</p>
        <h1>Set up two-factor authentication</h1>
        <p className="alert">
          Enrolment could not be started{enrollError ? `: ${enrollError.message}` : '.'}
        </p>
      </main>
    )
  }

  return (
    <main className="shell narrow">
      <p className="brand">PostDeck</p>
      <h1>Set up two-factor authentication</h1>
      <p className="lede">
        PostDeck cannot show you any business data until an authenticator app is linked to your
        account.
      </p>

      {message ? <p className="alert">{message}</p> : null}

      {enrolled ? (
        <div className="panel">
          <p>1. Scan this code with your authenticator app.</p>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img className="qr" src={enrolled.totp.qr_code} alt="TOTP enrolment QR code" />
          <p className="muted" style={{ marginTop: 12 }}>
            Cannot scan? Enter this key by hand:{' '}
            <span className="secret">{enrolled.totp.secret}</span>
          </p>
        </div>
      ) : (
        <div className="panel">
          <p>
            You already started setting this up. Enter the six-digit code from your authenticator
            app below.
          </p>
          <form action={restartEnrollmentAction}>
            {await csrfField()}
            <button type="submit" className="secondary">
              Lost it? Start over with a new QR code
            </button>
          </form>
        </div>
      )}

      <form action={confirmEnrollmentAction} className="panel">
        {await csrfField()}
        <input type="hidden" name="factorId" value={factorId} />
        <div className="field">
          <label htmlFor="code">2. Enter the six-digit code</label>
          <input
            id="code"
            name="code"
            className="code-input"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
          />
        </div>
        <button type="submit">Confirm and continue</button>
      </form>

      <form action={signOutAction}>
        {await csrfField()}
        <button type="submit" className="secondary">
          Sign out
        </button>
      </form>
    </main>
  )
}
