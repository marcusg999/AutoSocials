import { redirect } from 'next/navigation'

import { csrfField } from '@/lib/security/csrf'
import { resolveSessionState } from '@/lib/security/session'
import { DASHBOARD_PATH, LOGIN_PATH, MFA_VERIFY_PATH } from '@/lib/security/routes'
import { signOutAction } from '@/app/actions'

import { confirmEnrollmentAction } from './actions'

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

  // Discard any half-finished enrolment so a user cannot accumulate dead factors.
  const { data: existing } = await supabase.auth.mfa.listFactors()
  for (const factor of existing?.all ?? []) {
    if (factor.factor_type === 'totp' && factor.status === 'unverified') {
      await supabase.auth.mfa.unenroll({ factorId: factor.id })
    }
  }

  const { data: enrolled, error: enrollError } = await supabase.auth.mfa.enroll({ factorType: 'totp' })

  if (enrollError || !enrolled) {
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

      <div className="panel">
        <p>1. Scan this code with your authenticator app.</p>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img className="qr" src={enrolled.totp.qr_code} alt="TOTP enrolment QR code" />
        <p className="muted" style={{ marginTop: 12 }}>
          Cannot scan? Enter this key by hand: <span className="secret">{enrolled.totp.secret}</span>
        </p>
      </div>

      <form action={confirmEnrollmentAction} className="panel">
        {await csrfField()}
        <input type="hidden" name="factorId" value={enrolled.id} />
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
